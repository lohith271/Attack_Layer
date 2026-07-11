FROM python:3.12-slim

# Install system dependencies needed for LightGBM, XGBoost, and other libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .

# 1. Install CPU-only version of PyTorch first to save ~2.4 GB of download size
RUN pip install --no-cache-dir --default-timeout=1000 torch --index-url https://download.pytorch.org/whl/cpu

# 2. Install the rest of the packages (pip will see torch is already satisfied and skip it)
RUN pip install --no-cache-dir --default-timeout=1000 -r requirements.txt

# Copy the rest of the backend files
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Start command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
