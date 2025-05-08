FROM python:3.13.3-slim-bookworm

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY proxy.py .

# Set target IP as environment variable with default value
ENV TARGET_HOST=192.168.14.50

# Create volume for certificate persistence
VOLUME ["/app/certs"]

# Expose HTTPS port
EXPOSE 443

# Run the proxy with the target host
CMD ["sh", "-c", "python proxy.py ${TARGET_HOST}"] 