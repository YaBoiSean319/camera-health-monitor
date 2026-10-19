"""Small OIDC authorization-code + PKCE client and ID-token validator."""
import base64
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class OIDCError(ValueError):
    pass


def _http_json(url, *, method="GET", data=None, headers=None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return json.loads(response.read(1_000_000))
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        raise OIDCError("Identity provider is unavailable or returned invalid data") from error


def _b64decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def allowed_issuer(issuer):
    parsed = urllib.parse.urlparse(issuer)
    return parsed.scheme == "https" or parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "::1", "localhost")


def discover(issuer):
    if not allowed_issuer(issuer) or issuer.rstrip("/") != issuer:
        raise OIDCError("Issuer must be an HTTPS URL (HTTP is allowed only on loopback for testing)")
    metadata = _http_json(issuer + "/.well-known/openid-configuration")
    if not isinstance(metadata, dict):
        raise OIDCError("Identity provider discovery response is invalid")
    if metadata.get("issuer", "").rstrip("/") != issuer:
        raise OIDCError("Identity provider issuer does not match configuration")
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        endpoint = metadata.get(name, "")
        if not isinstance(endpoint, str) or not allowed_issuer(endpoint):
            raise OIDCError("Identity provider metadata contains an invalid endpoint")
    return metadata


def authorization_url(config, redirect_uri, state, nonce, verifier):
    metadata = discover(config["issuer"])
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": config["client_id"], "redirect_uri": redirect_uri,
        "scope": "openid profile email", "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    return metadata["authorization_endpoint"] + "?" + query


def exchange_and_validate(config, code, redirect_uri, verifier, expected_nonce):
    metadata = discover(config["issuer"])
    form = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                                   "client_id": config["client_id"], "client_secret": config["client_secret"], "code_verifier": verifier}).encode()
    token = _http_json(metadata["token_endpoint"], method="POST", data=form,
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
    if not isinstance(token, dict) or not isinstance(token.get("id_token"), str):
        raise OIDCError("Identity provider did not return an ID token")
    parts = token["id_token"].split(".")
    if len(parts) != 3:
        raise OIDCError("Identity provider returned a malformed ID token")
    try:
        header = json.loads(_b64decode(parts[0]))
        claims = json.loads(_b64decode(parts[1]))
    except (ValueError, TypeError) as error:
        raise OIDCError("Identity provider returned a malformed ID token") from error
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise OIDCError("Identity provider returned a malformed ID token")
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise OIDCError("ID token uses an unsupported signing algorithm")
    jwks = _http_json(metadata["jwks_uri"])
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys", []), list):
        raise OIDCError("Identity provider signing keys are invalid")
    key = next((item for item in jwks.get("keys", []) if isinstance(item, dict) and item.get("kid") == header["kid"] and item.get("kty") == "RSA"), None)
    if not key:
        raise OIDCError("Identity provider signing key was not found")
    try:
        public = rsa.RSAPublicNumbers(int.from_bytes(_b64decode(key["e"]), "big"), int.from_bytes(_b64decode(key["n"]), "big")).public_key()
        public.verify(_b64decode(parts[2]), f"{parts[0]}.{parts[1]}".encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception as error:
        raise OIDCError("ID token signature is invalid") from error
    now = time.time()
    issuer = claims.get("iss")
    audiences = claims.get("aud", [])
    audiences = [audiences] if isinstance(audiences, str) else audiences
    if (not isinstance(issuer, str) or issuer.rstrip("/") != config["issuer"]
            or not isinstance(audiences, list) or not all(isinstance(item, str) for item in audiences)
            or config["client_id"] not in audiences):
        raise OIDCError("ID token issuer or audience is invalid")
    if len(audiences) > 1 and claims.get("azp") != config["client_id"]:
        raise OIDCError("ID token authorized party is invalid")
    if not isinstance(claims.get("exp"), (int, float)) or isinstance(claims.get("exp"), bool) or claims["exp"] <= now:
        raise OIDCError("ID token has expired")
    if not isinstance(claims.get("iat"), (int, float)) or isinstance(claims.get("iat"), bool) or claims["iat"] > now + 60:
        raise OIDCError("ID token issued-at time is invalid")
    if claims.get("nbf") is not None and (not isinstance(claims["nbf"], (int, float)) or claims["nbf"] > now + 60):
        raise OIDCError("ID token is not yet valid")
    if claims.get("nonce") != expected_nonce or not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise OIDCError("ID token nonce or subject is invalid")
    return claims


def mapped_role(claims, claim_name, administrator_values, operator_values):
    value = claims
    for segment in claim_name.split("."):
        value = value.get(segment) if isinstance(value, dict) else None
    values = value if isinstance(value, list) else [value]
    values = {item for item in values if isinstance(item, str)}
    if values.intersection(administrator_values):
        return "administrator"
    if values.intersection(operator_values):
        return "operator"
    return None
