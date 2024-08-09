
# Minimalistic Python HTTPS Proxy

A minimalistic Python HTTPS proxy that forwards requests to an HTTP-only server, enabling modern systems to communicate with older devices that only support HTTP.

## Installation

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/kimasplund/minimal-proxy.git 
cd minimal-proxy
pip install -r requirements.txt
```

## Usage

Run the proxy server by specifying the target HTTP host:

```bash
python3 proxy.py <target_http_host>
```

### Running in the Background

To run the proxy server in the background with no logging:

```bash
nohup python3 proxy.py <target_http_host> > /dev/null 2>&1 &
```

Replace `<target_http_host>` with the IP address or hostname of the server you want to forward requests to.
