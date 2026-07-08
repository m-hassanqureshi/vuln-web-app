# Use official lightweight Python image
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Copy lock and project files first to leverage caching
COPY pyproject.toml uv.lock ./

# Install uv package manager and install dependencies
RUN pip install --no-cache-dir uv && \
    uv pip install --system -r pyproject.toml

# Copy project source code into container
COPY . .

# Expose standard port 3001
EXPOSE 3001

# Run uvicorn server mapping port 3001
CMD ["python", "backend/app/main.py"]
