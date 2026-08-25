# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first so this layer stays cached unless requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code + the committed FAISS index / MITRE data
COPY . .

# Run as a non-root user (good container hygiene)
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

EXPOSE 8501

# Streamlit must bind 0.0.0.0 to be reachable from outside the container
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
