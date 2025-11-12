# Use Python 3.9 as base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files
COPY requirements.txt requirements-notifications.txt requirements-visualization.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-notifications.txt
RUN pip install --no-cache-dir -r requirements-visualization.txt

# Copy application code
COPY . .

# Create directories for runtime data
RUN mkdir -p cache tenants runs

# Expose port for web interface
EXPOSE 5000

# Create non-root user
RUN useradd --create-home --shell /bin/bash penai
USER penai

# Set environment variables
ENV PYTHONPATH=/app
ENV PENAI_CONFIG_DIR=/app/configs

# Default command
CMD ["python", "agent.py", "--help"]