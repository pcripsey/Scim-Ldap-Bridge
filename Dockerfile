FROM node:22-alpine AS console
WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web ./
RUN npm run build

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BRIDGE_DATA_DIR=/data

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 bridge \
    && useradd --uid 10001 --gid bridge --no-create-home bridge \
    && mkdir /data \
    && chown bridge:bridge /data \
    && chmod 700 /data
COPY bridge ./bridge
COPY --from=console /web/dist ./web/dist

USER bridge
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"
CMD ["uvicorn", "bridge.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]