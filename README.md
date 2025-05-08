# Minimal Proxy

A minimal HTTPS proxy that forwards requests to a target HTTP server.

## Features

- HTTPS server with auto-generated SSL certificate
- Proxies HTTP requests to a target server
- Supports GET and POST methods
- Docker containerized for easy deployment
- Uses Python 3.13 Alpine for a minimal footprint

## Usage

### Direct Python Usage

```bash
# Install requirements
pip install -r requirements.txt

# Run the proxy (replace example.com with your target)
python proxy.py example.com
```

### Docker Usage

```bash
# Build and start the Docker container
docker-compose up -d

# The proxy will target 192.168.14.50 by default
```

### Customizing Target IP

You can change the target IP in docker-compose.yml:

```yaml
environment:
  - TARGET_HOST=your-target-ip-or-hostname
```

### Certificates

Certificates are generated automatically on first run and stored in the `certs` directory. The Docker container mounts this directory as a volume to persist certificates between restarts.

## Testing

The repository includes a testing framework to verify the proxy connection:

```bash
# Run tests using the test Docker Compose configuration
docker-compose -f docker-compose.test.yml up --build

```

The test script will:
1. Send GET and POST requests to the proxy
2. Verify connections to the target IP
3. Report success or failure
