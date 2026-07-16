FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////app/instance/domain-oss.db \
    PORT=8080 \
    WORKERS=2

RUN addgroup --system domainoss && adduser --system --ingroup domainoss domainoss
WORKDIR /app
COPY pyproject.toml README.md ./
COPY domain_oss ./domain_oss
RUN pip install --no-cache-dir .
RUN mkdir -p /app/instance && chown -R domainoss:domainoss /app

USER domainoss
EXPOSE 8080
VOLUME ["/app/instance"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"

CMD ["sh", "-c", "domain-oss init-db && exec gunicorn --workers ${WORKERS} --bind 0.0.0.0:${PORT} --access-logfile - --error-logfile - --timeout 30 'domain_oss:create_app()'"]
