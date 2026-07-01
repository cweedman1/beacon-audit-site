FROM python:3.12.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BEACON_HOME=/tmp/beacon \
    BEACON_TEMP=/tmp/beacon/temp \
    CHROME_PATH=/usr/bin/chromium

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg chromium fonts-liberation \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && npm install --omit=dev --no-save lighthouse@13.4.0 \
    && mkdir -p /tmp/beacon/temp

COPY api ./api
COPY *.html ./
COPY css ./css
COPY js ./js
COPY assets ./assets
COPY includes ./includes
COPY knowledge ./knowledge
COPY reports ./reports
COPY docs ./docs
COPY robots.txt sitemap.xml CNAME .nojekyll ./

EXPOSE 8000

CMD ["sh", "-c", "uvicorn api.app:app --host 0.0.0.0 --port ${PORT:-8000}"]