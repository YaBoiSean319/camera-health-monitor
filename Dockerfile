FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CHM_DATA_DIR=/data \
    CHM_HOST=0.0.0.0 \
    CHM_PORT=8080

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./app.py
COPY oidc.py ./oidc.py
COPY branding.py ./branding.py
COPY scheduler.py ./scheduler.py
COPY web ./web
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin chm \
    && mkdir -p /data \
    && chown chm:chm /data
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=2)"
CMD ["python", "app.py"]
