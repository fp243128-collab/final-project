FROM python:3.11-slim

WORKDIR /app

# Ensure pip, setuptools and wheel are updated, install requirements using pre-compiled wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --prefer-binary -r requirements.txt

# Copy backend source
COPY . .

# Expose port
EXPOSE 8000

# Start FastAPI using Uvicorn with dynamic PORT support for PaaS (Railway / Render / Cloud Run)
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]

