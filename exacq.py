"""Version-specific ExacqVision Web Service client.

The routes and payloads here are based on the 21.12.1 Web Client API observed
in sanitized traffic: login.web, config.web, server.web/devices, video.web,
search.web, search.web/status, playspeed.web, step.web, and timestamp.web.
These are Web Client interfaces rather than a vendor-published stable API.
"""

from __future__ import annotations

import json
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone


TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_SEARCH_WAIT_SECONDS = 15


class ExacqError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.safe_message = message


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ExacqClient:
    """One short-lived authenticated session; session IDs never leave this module."""

    def __init__(self, server, username, password, timeout=TIMEOUT_SECONDS):
        self.host = server["host"].strip().strip("[]")
        self.scheme = server.get("web_scheme", "http")
        self.port = server.get("web_port") or (443 if self.scheme == "https" else 80)
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session_id = None
        self.opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    @property
    def origin(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        default_port = 443 if self.scheme == "https" else 80
        return f"{self.scheme}://{host}" + (f":{self.port}" if self.port != default_port else "")

    def _request(self, path, params=None, data=None, expected=None, retry_auth=True):
        params = dict(params or {})
        url = self.origin + path
        if params:
            cache_bust = params.pop("_cache_bust", None)
            fields = [urllib.parse.quote(str(key), safe="") + "=" + urllib.parse.quote(str(value), safe="")
                      for key, value in params.items()]
            if cache_bust is not None:
                fields.append(urllib.parse.quote(str(cache_bust), safe=""))
            url += "?" + ";".join(fields)
        headers = {"User-Agent": "CameraHealthMonitor/1.0", "Accept": "application/json, image/jpeg, */*"}
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                status = response.status
                mime = response.headers.get_content_type()
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            status = error.code
            if status in (401, 403):
                if status == 401 and retry_auth and "s" in params and self.password:
                    self.session_id = None
                    self.login()
                    params["s"] = self.session_id
                    return self._request(path, params, data, expected, retry_auth=False)
                raise ExacqError("permission_denied", "ExacqVision rejected authentication or access.") from None
            if status in (301, 302, 303, 307, 308):
                raise ExacqError("unsupported_response", "ExacqVision redirected the request; redirects are not followed.") from None
            raise ExacqError("recorder_unavailable", "ExacqVision returned an HTTP error.") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ExacqError("recorder_unavailable", "The ExacqVision Web Service could not be reached.") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ExacqError("response_too_large", "ExacqVision returned an oversized response.")
        if expected and mime not in expected:
            raise ExacqError("unsupported_response", "ExacqVision returned an unexpected response type.")
        return status, mime, raw

    @staticmethod
    def _json(raw):
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ExacqError("malformed_response", "ExacqVision returned an invalid JSON response.") from None
        if not isinstance(value, dict):
            raise ExacqError("malformed_response", "ExacqVision returned an unexpected JSON shape.")
        return value

    def login(self):
        # This is the ordinary Web Client credential login, distinct from the
        # browser's loginToken flow, which uses a transient token from its UI.
        _, _, raw = self._request("/login.web", data={
            "u": self.username, "p": self.password, "l": "1", "s": "0",
            "output": "json", "responseVersion": "2",
        })
        result = self._json(raw)
        if not result.get("success"):
            raise ExacqError("permission_denied", "ExacqVision did not accept the configured credentials.")
        session_id = result.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise ExacqError("malformed_response", "ExacqVision did not return an authenticated session.")
        self.session_id = session_id
        return result

    def _session_json(self, path, params=None):
        if not self.session_id:
            self.login()
        query = {"s": self.session_id, **(params or {})}
        _, _, raw = self._request(path, query)
        result = self._json(raw)
        if result.get("success") is False:
            # Sessions are deliberately short-lived. One fresh login handles an
            # expired session without persisting or exposing session material.
            self.session_id = None
            self.login()
            query["s"] = self.session_id
            _, _, raw = self._request(path, query)
            result = self._json(raw)
            if result.get("success") is False:
                raise ExacqError("permission_denied", "ExacqVision denied this operation.")
        return result

    def discover(self):
        login = self.login()
        config = self._session_json("/config.web", {"output": "json", "showAll": "0"})
        devices = self._session_json("/server.web/devices")
        statuses = self._session_json("/status.web")
        cameras = config.get("Cameras")
        device_rows = devices.get("devices", [])
        if not isinstance(cameras, list) or not isinstance(device_rows, list):
            raise ExacqError("malformed_response", "ExacqVision camera inventory has an unexpected shape.")
        device_by_camera = {}
        for device in device_rows:
            if not isinstance(device, dict):
                continue
            for association in device.get("cameras", []) or []:
                camera_id = association.get("cameraId")
                if camera_id is not None:
                    device_by_camera[str(camera_id)] = device
        discovered = []
        for camera in cameras:
            if not isinstance(camera, dict) or camera.get("id") is None:
                continue
            remote_id = str(camera["id"])
            device = device_by_camera.get(remote_id, {})
            is_disabled = bool(int(camera.get("disabled", 0) or 0)) or device.get("enabled") is False
            connected = device.get("isConnected")
            if connected is None and camera.get("state") in (0, 1):
                connected = camera.get("state") == 0
            discovered.append({
                "remote_id": remote_id,
                "name": str(camera.get("name") or f"Camera {remote_id}")[:250],
                "parent_remote_id": str(camera.get("parentId", camera.get("p", ""))),
                "disabled": is_disabled,
                "connection_state": "disabled" if is_disabled else ("connected" if connected is True else "disconnected" if connected is False else "unknown"),
                "metadata": {
                    key: value for key, value in {
                        "manufacturer": device.get("type"), "model": device.get("model"),
                        "device_ip": device.get("host"), "firmware": device.get("firmware"),
                        "device_id": str(device.get("id")) if device.get("id") is not None else None,
                        "enabled": device.get("enabled"), "is_connected": connected,
                        "resolution": camera.get("resolution"), "frame_rate": camera.get("frameRate"),
                        "stream_formats": camera.get("streamFormats"), "formats": camera.get("formats"),
                        "state": camera.get("state"),
                    }.items() if value is not None
                },
            })
        return {"cameras": discovered, "version": login.get("version"), "server_status": (statuses.get("statuses") or [{}])[0].get("serverStatus")}

    def test_connection(self):
        login = self.login()
        status = self._session_json("/status.web")
        return {"version": login.get("version"),
                "server_status": (status.get("statuses") or [{}])[0].get("serverStatus")}

    @staticmethod
    def _decode_jpeg(data):
        try:
            result = subprocess.run([
                "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-f", "image2pipe",
                "-vcodec", "mjpeg", "-i", "pipe:0", "-frames:v", "1", "-f", "null", "-",
            ], input=data, capture_output=True, timeout=15, check=False)
        except FileNotFoundError:
            raise ExacqError("decoder_unavailable", "FFmpeg is not installed in the monitor container.") from None
        except subprocess.TimeoutExpired:
            raise ExacqError("timeout", "Video decoding exceeded its time limit.") from None
        if result.returncode:
            raise ExacqError("decode_failed", "FFmpeg could not decode a video frame.")

    def _jpeg(self, path, params):
        _, mime, raw = self._request(path, params)
        if mime != "image/jpeg" or len(raw) < 4 or not raw.startswith(b"\xff\xd8") or not raw.endswith(b"\xff\xd9"):
            raise ExacqError("video_unavailable", "ExacqVision did not return a valid JPEG frame.")
        return raw

    def check_live(self, camera_id):
        started = time.monotonic()
        self.login()
        frames = []
        stream_id = str(uuid.uuid4())
        for index in range(3):
            _, mime, raw = self._request("/video.web", {
                "s": self.session_id, "camera": str(camera_id), "stream": stream_id,
                "w": "640", "h": "360", "q": "5", "format": "6", "_cache_bust": str(int(time.time() * 1000)),
            })
            if mime != "image/jpeg" or len(raw) < 4 or not raw.startswith(b"\xff\xd8") or not raw.endswith(b"\xff\xd9"):
                raise ExacqError("video_unavailable", "ExacqVision did not return a valid JPEG frame.")
            self._decode_jpeg(raw)
            frames.append(raw)
            if index != 2:
                time.sleep(0.5)
        return {"decoded": True, "frames_decoded": len(frames), "media_format": "image/jpeg",
                "frame_count": len(frames), "duration_ms": round((time.monotonic() - started) * 1000),
                "sample_timestamp": None, "freshness_verified": False, "decoder": "ffmpeg",
                "detail": "Three live-endpoint frames were decoded. ExacqVision supplied no source capture timestamp, so wall-clock freshness cannot be independently confirmed."}

    def live_frame(self, camera_id, stream_id):
        """Retrieve one JPEG frame for a short-lived browser live-view session."""
        if not self.session_id:
            self.login()
        return self._jpeg("/video.web", {
            "s": self.session_id, "camera": str(camera_id), "stream": str(stream_id),
            "w": "1280", "h": "720", "q": "5", "format": "6",
            "_cache_bust": str(int(time.time() * 1000)),
        })

    def _search(self, camera_id, start, end):
        result = self._session_json("/search.web", {"camera": str(camera_id), "start": start, "end": end, "output": "json"})
        deadline = time.monotonic() + MAX_SEARCH_WAIT_SECONDS
        while time.monotonic() < deadline:
            status = self._session_json("/search.web/status")
            state = (status.get("status") or {}).get("status")
            if state in (2, "2", "complete", "completed", "done"):
                return result
            if state in (3, "3", "failed", "error"):
                raise ExacqError("recording_search_failed", "ExacqVision recording search did not complete.")
            time.sleep(0.25)
        raise ExacqError("timeout", "ExacqVision recording search exceeded its time limit.")

    @staticmethod
    def _clips(result):
        clips = []
        for item in result.get("videoInfo", []) or []:
            if not isinstance(item, dict):
                continue
            for clip in item.get("clips", []) or []:
                if isinstance(clip, dict) and clip.get("startTime"):
                    clips.append(clip)
        for clip in result.get("clips", []) or []:
            if isinstance(clip, dict) and clip.get("startTime"):
                clips.append(clip)
        return clips

    def check_recording(self, camera_id, lookback_hours):
        started = time.monotonic()
        self.login()
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt.timestamp() - int(lookback_hours) * 3600
        iso = lambda ts: datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = self._search(camera_id, iso(start_dt), iso(end_dt.timestamp()))
        clips = self._clips(result)
        if not clips and int(result.get("frames", 0) or 0) == 0:
            return {"health": "warning", "reason": "no_recent_recording", "newest_recording_at": None,
                    "decoded": False, "duration_ms": round((time.monotonic() - started) * 1000),
                    "evidence": {"frame_count": 0, "lookback_hours": int(lookback_hours)}}
        def clip_end(clip):
            value = clip.get("endTime") or clip.get("startTime")
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            except (ValueError, AttributeError):
                return 0
        newest = max(clips, key=clip_end) if clips else None
        if newest is None:
            raise ExacqError("malformed_response", "ExacqVision reported recording frames but no recording interval.")
        newest_time = newest.get("endTime") or newest.get("startTime")
        try:
            segment_start = datetime.fromisoformat(newest["startTime"].replace("Z", "+00:00")).timestamp()
            segment_end = datetime.fromisoformat((newest.get("endTime") or newest["startTime"]).replace("Z", "+00:00")).timestamp()
        except (ValueError, AttributeError):
            raise ExacqError("malformed_response", "ExacqVision returned an invalid recording interval.") from None
        segment_start = max(start_dt, segment_start)
        segment_end = min(end_dt.timestamp(), segment_end)
        if segment_end < segment_start:
            raise ExacqError("malformed_response", "ExacqVision returned a recording outside the requested lookback window.")
        # Re-run a narrow search inside the newest clip; playback frame 0 is then
        # guaranteed to reference recorded media rather than the broad search's gap.
        sample = self._search(camera_id, iso(segment_start), iso(max(segment_start + 1, segment_end)))
        search_id = sample.get("search_id")
        if not isinstance(search_id, str) or not search_id:
            raise ExacqError("malformed_response", "ExacqVision did not return a playback search handle.")
        self._request("/playspeed.web/0", {"search_id": search_id})
        _, _, step_raw = self._request("/step.web/0", {"search_id": search_id, "output": "json"})
        self._json(step_raw)
        frame = self._jpeg("/video.web", {"s": self.session_id, "camera": str(camera_id),
                                            "stream": str(uuid.uuid4()), "search_id": search_id,
                                            "w": "640", "h": "360", "q": "5", "format": "6"})
        self._decode_jpeg(frame)
        _, _, timestamp_raw = self._request("/timestamp.web", {"search_id": search_id, "output": "json"})
        timestamp = self._json(timestamp_raw)
        sample_time = timestamp.get("time") if isinstance(timestamp.get("time"), str) else newest_time
        return {"health": "healthy", "reason": None, "newest_recording_at": newest_time,
                "recorded_sample_at": sample_time, "decoded": True,
                "duration_ms": round((time.monotonic() - started) * 1000),
                "evidence": {"frame_count": int(result.get("frames", 0) or 0), "decoder": "ffmpeg",
                             "media_format": "image/jpeg", "freshness_verified": bool(timestamp.get("time")),
                             "detail": "Newest recorded search sample retrieved and decoded."}}
