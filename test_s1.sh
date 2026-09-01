#!/bin/bash
set -e
cd /root/chitanda_test
pkill -f xray-chitanda || true
pkill -f fallback.py || true

# 1. Generate TLS certificate
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=status.chitanda.test" -addext "subjectAltName=DNS:status.chitanda.test,IP:168.138.209.1" 2>/dev/null || true

# 2. Start fallback web server on 8080
cat << 'EOF' > fallback.py
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"VANGUARD OPERATIONS HUB FALLBACK OK\n")
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"VANGUARD OPERATIONS HUB FALLBACK OK\n")
    def log_message(self, format, *args):
        pass
HTTPServer(('127.0.0.1', 8080), Handler).serve_forever()
EOF
nohup python3 fallback.py > fallback.log 2>&1 &

# 3. Create Xray Server configuration
cat << 'EOF' > server_config.json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "inbound-tls",
      "port": 28443,
      "protocol": "chitanda",
      "settings": {
        "psk": "chitanda-test-psk-key-32bytes-secret",
        "path": "/api/v1/sync",
        "transport": "h2",
        "strict_sni": "status.chitanda.test",
        "fallback": "127.0.0.1:8080"
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/root/chitanda_test/server.crt",
              "keyFile": "/root/chitanda_test/server.key"
            }
          ],
          "alpn": ["h2", "h3", "http/1.1"]
        }
      }
    },
    {
      "tag": "inbound-h1",
      "port": 28200,
      "protocol": "chitanda",
      "settings": {
        "psk": "chitanda-test-psk-key-32bytes-secret",
        "path": "/gateway/stream/v2",
        "transport": "h1",
        "fallback": "127.0.0.1:8080"
      },
      "streamSettings": {
        "security": "none"
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
EOF

# 4. Start Xray Server
nohup /root/chitanda_test/xray-chitanda-v26.3.27-linux-arm64 run -c server_config.json > server.log 2>&1 &
sleep 2

echo "=== SERVER PROCESS STATUS ==="
ps aux | grep xray-chitanda | grep -v grep

echo "=== SERVER LISTENING PORTS ==="
ss -tulpn | grep 28443 || true
ss -tulpn | grep 28200 || true

echo "=== TESTING LOCAL FALLBACK ==="
curl -k -s -H "Host: status.chitanda.test" https://127.0.0.1:28443/
curl -k -s -H "Host: wrong.domain.com" https://127.0.0.1:28443/
curl -s http://127.0.0.1:28200/unauthorized_access
