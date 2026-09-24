FROM python:3.11-slim

WORKDIR /app

# Install system dependencies needed for some ML libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY . .

# Expose port
EXPOSE 8000

# Start FastAPI using Uvicorn with dynamic PORT support for PaaS (Railway / Render / Cloud Run)
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
