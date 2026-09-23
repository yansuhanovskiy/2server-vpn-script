#!/bin/bash
#
# check-client.sh — проверка ссылки vless:// прямо на сервере №1.
# Поднимает временный Xray-клиент с параметрами из ссылки и делает запрос через него.
# Успех: печатается внешний IP (должен быть IP выходного сервера).
#
#   bash check-client.sh                  # ссылка из /root/vpn-access.txt
#   bash check-client.sh 'vless://...'    # своя ссылка

set -uo pipefail

LINK=${1:-$(grep -o 'vless://[^ ]*' /root/vpn-access.txt 2>/dev/null | head -n1)}
[[ $LINK == vless://* ]] || { echo "Нет ссылки vless://"; exit 1; }
XRAY=$(ls /usr/local/x-ui/bin/xray-linux-* 2>/dev/null | head -n1)
[[ -x $XRAY ]] || { echo "Не найден бинарник Xray"; exit 1; }

rest=${LINK#vless://}
uuid=${rest%%@*}
hostport=${rest#*@}; hostport=${hostport%%\?*}
port=${hostport##*:}
query=${rest#*\?}; query=${query%%#*}
param() { tr '&' '\n' <<<"$query" | awk -F= -v k="$1" '$1==k{print $2; exit}'; }
pbk=$(param pbk); sni=$(param sni); sid=$(param sid); flow=$(param flow); fp=$(param fp)

echo "uuid=$uuid port=$port sni=$sni sid=$sid flow=$flow pbk=$pbk"

tmp=$(mktemp -d)
trap 'kill $pid 2>/dev/null; rm -rf "$tmp"' EXIT
cat > "$tmp/c.json" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": false}}],
  "outbounds": [{
    "protocol": "vless",
    "settings": {"vnext": [{"address": "127.0.0.1", "port": $port,
      "users": [{"id": "$uuid", "encryption": "none", "flow": "$flow"}]}]},
    "streamSettings": {"network": "tcp", "security": "reality",
      "realitySettings": {"serverName": "$sni", "publicKey": "$pbk", "shortId": "$sid",
                          "fingerprint": "${fp:-chrome}", "spiderX": "/"}}
  }]
}
EOF

"$XRAY" run -c "$tmp/c.json" > "$tmp/log" 2>&1 &
pid=$!
sleep 2

ip=$(curl -sS --max-time 15 -x socks5h://127.0.0.1:10808 https://ipv4.icanhazip.com 2>&1 | tr -d '[:space:]')
if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "OK: через ссылку работает, внешний IP $ip"
    exit 0
fi
echo "FAIL: $ip"
echo "--- лог тестового клиента:"; cat "$tmp/log"
echo "--- лог x-ui:"; journalctl -u x-ui -n 15 --no-pager | tail -15
exit 1
