# Warden: API, console, pipeline, and nightly jobs in one image.
# docker build -t warden .

FROM node:24-slim AS console
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build   # writes ../warden/static/console

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    WARDEN_DATA_DIR=/data WARDEN_LOG_FORMAT=json
RUN useradd --create-home --uid 10001 warden
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY warden/ warden/
COPY --from=console /warden/static/console warden/static/console
COPY data/knowledge/ /app/seed/knowledge/
COPY data/eval/ /app/seed/eval/
COPY scripts/ scripts/
COPY docker-entrypoint.sh /usr/local/bin/
RUN mkdir -p /data && chown -R warden /data /app
USER warden
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=4).status==200 else 1)"
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["serve"]
