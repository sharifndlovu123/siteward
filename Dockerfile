FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DJANGO_SETTINGS_MODULE=webscan.web.settings
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY webscan ./webscan
RUN pip install --no-cache-dir . \
 && STATIC_ROOT=/app/staticfiles django-admin collectstatic --noinput \
 && useradd --system --no-create-home app \
 && mkdir -p /var/log/webscan && chown app /var/log/webscan
ENV STATIC_ROOT=/app/staticfiles
USER app
EXPOSE 8000
# One worker + threads: scan results live in this process's memory. No access log by design.
CMD ["gunicorn", "webscan.web.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "--timeout", "60"]
