FROM python:3.9-slim

WORKDIR /app

# Install system dependencies if required for heuristics/magic bytes
RUN apt-get update && apt-get install -y --no-install-recommends \
    file \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Use gunicorn in production if available, else fallback to simple python run
CMD ["python", "main.py"]
