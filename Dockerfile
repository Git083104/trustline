FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRUSTMAP_ALLOW_LOCAL_SCAN=0 \
    TRUSTMAP_CACHE_DB=/var/data/trustmap.db
RUN mkdir -p /var/data
COPY pyproject.toml README.md ./
COPY scanner ./scanner
COPY api ./api
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["sh", "-c", "uvicorn api.main:app --factory --host 0.0.0.0 --port ${PORT:-8000}"]
