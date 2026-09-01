#!/bin/bash
set -e
cd /root/chitanda_test

echo "================================================================"
echo "  TESTING MIHOMO (CLASH.META) CLIENT ACROSS ALL 4 MODES"
echo "================================================================"

for MODE in "h2" "h3" "auto" "h1"; do
    PORT="28443"
    PATH_URI="/api/v1/sync"
    SNI="sni: \"status.chitanda.test\""
    SKIP="skip-cert-verify: true"
    
    if [ "$MODE" == "h1" ]; then
        PORT="28200"
        PATH_URI="/gateway/stream/v2"
        SNI=""
        SKIP=""
    fi
    
    pkill -f mihomo-chitanda || true
    cat << EOF > test_mihomo.yaml
port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: warning

proxies:
  - name: "test-node"
    type: chitanda
    server: 168.138.209.1
    port: $PORT
    psk: "chitanda-test-psk-key-32bytes-secret"
    path: "$PATH_URI"
    transport: "$MODE"
    $SNI
    $SKIP
    udp: true

rules:
  - MATCH,test-node
EOF

    nohup /root/chitanda_test/mihomo-chitanda-v1.19.30-linux-amd64 -f test_mihomo.yaml > mihomo.log 2>&1 &
    sleep 3

    echo "--- [Mihomo Mode: ${MODE^^}] ---"
    HTTP_RES=$(curl -sL -k -m 12 -x socks5h://127.0.0.1:7891 https://1.1.1.1/cdn-cgi/trace 2>&1 || true)
    if echo "$HTTP_RES" | grep -q "fl="; then
        IP_VAL=$(echo "$HTTP_RES" | grep "^ip=" | cut -d= -f2)
        echo "  [SUCCESS] Traffic successfully proxied via Server 1! Exit IP: $IP_VAL"
    else
        echo "  [FAIL/DETAIL]: $HTTP_RES"
        cat mihomo.log | tail -n 10
    fi
done

echo ""
echo "================================================================"
echo "  TESTING XRAY-CORE CLIENT ACROSS ALL 4 MODES"
echo "================================================================"

for MODE in "h2" "h3" "auto" "h1"; do
    PORT="28443"
    PATH_URI="/api/v1/sync"
    STREAM_CFG='{
      "security": "tls",
      "tlsSettings": {
        "serverName": "status.chitanda.test",
        "certificates": [
          {
            "usage": "verify",
            "certificateFile": "/root/chitanda_test/server.crt"
          }
        ],
        "alpn": ["h2", "h3", "http/1.1"]
      }
    }'
    
    if [ "$MODE" == "h1" ]; then
        PORT="28200"
        PATH_URI="/gateway/stream/v2"
        STREAM_CFG='{
          "security": "none"
        }'
    fi
    
    pkill -f xray-chitanda || true
    cat << EOF > test_xray_client.json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "socks-in",
      "port": 10808,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": { "udp": true }
    }
  ],
  "outbounds": [
    {
      "tag": "chitanda-out",
      "protocol": "chitanda",
      "settings": {
        "server": "168.138.209.1:$PORT",
        "server_name": "status.chitanda.test",
        "psk": "chitanda-test-psk-key-32bytes-secret",
        "path": "$PATH_URI",
        "transport": "$MODE"
      },
      "streamSettings": $STREAM_CFG
    }
  ]
}
EOF

    nohup /root/chitanda_test/xray-chitanda-v26.3.27-linux-amd64 run -c test_xray_client.json > xray_client.log 2>&1 &
    sleep 3

    echo "--- [Xray Client Mode: ${MODE^^}] ---"
    HTTP_RES=$(curl -sL -k -m 12 -x socks5h://127.0.0.1:10808 https://1.1.1.1/cdn-cgi/trace 2>&1 || true)
    if echo "$HTTP_RES" | grep -q "fl="; then
        IP_VAL=$(echo "$HTTP_RES" | grep "^ip=" | cut -d= -f2)
        echo "  [SUCCESS] Traffic successfully proxied via Server 1! Exit IP: $IP_VAL"
    else
        echo "  [FAIL/DETAIL]: $HTTP_RES"
        cat xray_client.log | tail -n 10
    fi
done

pkill -f mihomo-chitanda || true
pkill -f xray-chitanda || true
