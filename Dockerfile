FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PORT=8787

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-verifier.txt ./
RUN pip install --no-cache-dir -r requirements-verifier.txt

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
# Copy the whole directory, not individual files. Listing verifier scripts one by one means
# a newly added scheme's script is missing in production while the deploy still reports
# success - the API serves fine and only real signature verification fails.
COPY scripts ./scripts
COPY openapi.json ./openapi.json

EXPOSE 8787

CMD ["sh", "-c", "python -m bitmap_memory_portal.verifier_http --host 0.0.0.0 --port ${PORT}"]
