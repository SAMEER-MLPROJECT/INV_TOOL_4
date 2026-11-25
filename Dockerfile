FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SAKSHYA_DATA_DIR=/data \
    SAKSHYA_ENV=production \
    PORT=8000

WORKDIR /app
COPY requirements.lock .
RUN pip install --require-hashes -r requirements.lock
COPY sakshya ./sakshya
RUN chmod -R a+rX,go-w /app/sakshya

RUN groupadd --system sakshya \
    && useradd --system --gid sakshya --home-dir /app --shell /usr/sbin/nologin sakshya \
    && mkdir -p /data \
    && chown sakshya:sakshya /data \
    && chmod 0750 /data

USER sakshya
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/api/health/live' % os.environ.get('PORT','8000'), timeout=4)"
CMD ["sh", "-c", "exec python -m sakshya serve --host 0.0.0.0 --port ${PORT}"]
