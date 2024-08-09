# pip install -r requirements.txt
# python3 proxy.py <target_http_host>
# Or to run in the background with no logging.
# nohup python3 proxy.py <target_http_host> > /dev/null 2>&1 &
import os
import http.server
import ssl
import requests
import sys
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

CERT_FILE = 'server.cert'
KEY_FILE = 'server.key'

def generate_cert_and_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 1)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    with open(CERT_FILE, "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

class ProxyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.target_http_host = kwargs.pop('target_http_host')
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.proxy_request('GET')

    def do_POST(self):
        self.proxy_request('POST')

    def proxy_request(self, method):
        target_url = f"http://{self.target_http_host}{self.path}"
        headers = {key: self.headers[key] for key in self.headers}
        response = requests.get(target_url, headers=headers, allow_redirects=False) if method == 'GET' else requests.post(
            target_url, data=self.rfile.read(int(self.headers.get('Content-Length', 0))), headers=headers, allow_redirects=False)
        self.send_response(response.status_code)
        for key, value in response.headers.items():
            if key.lower() != 'transfer-encoding':
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(response.content)

def run(server_class=http.server.HTTPServer, handler_class=ProxyHTTPRequestHandler, https_port=443, target_http_host='example.com'):
    def handler(*args, **kwargs):
        handler_class(*args, target_http_host=target_http_host, **kwargs)

    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        generate_cert_and_key()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    httpd = server_class(('0.0.0.0', https_port), handler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 proxy.py <target_http_host>")
        sys.exit(1)

    target_http_host = sys.argv[1]
    run(target_http_host=target_http_host)
