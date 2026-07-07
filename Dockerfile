FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Node + npm so the scanner can run `npm audit` on the frontend lockfile.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

EXPOSE 8000

# Default: run the pipeline web service (webhook receiver + dashboard).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
