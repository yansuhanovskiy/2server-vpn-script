#!/bin/bash
#
# test-variants.sh — создаёт в 3x-ui несколько тестовых inbound'ов с разными
# настройками маскировки и печатает ссылки, чтобы понять, какой вариант
# проходит через DPI провайдера. Запускать на сервере №1 после entry-server.sh.
#
#   SNI=firstvds.ru bash test-variants.sh
#
# Повторный запуск пересоздаёт тестовые inbound'ы (remark начинается с test-).

set -euo pipefail

SNI=${SNI:-firstvds.ru}
XUI_DIR=/usr/local/x-ui
CONF=/etc/l2tp-exit/xui.env

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "Запустите от root."
[[ -f $CONF ]] || die "Нет $CONF — сначала запустите entry-server.sh"
# shellcheck disable=SC1090
. "$CONF"

TOKEN=$($XUI_DIR/x-ui setting -getApiToken 2>/dev/null | grep -Eo 'apiToken: .+' | awk '{print $2}')
[[ -n $TOKEN ]] || die "Не удалось получить API-токен 3x-ui"
BASE="http://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH"
PUBLIC_IP=$(curl -4 -fsS --max-time 5 --interface "$(ip -4 route get 1.1.1.1 | grep -oP 'src \K\S+')" https://ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]') || true
[[ -n $PUBLIC_IP ]] || PUBLIC_IP=$(ip -4 -o addr show scope global | awk '{split($4,a,"/"); print a[1]; exit}')

api() {
    local method=$1 path=$2 data=${3:-}
    local args=(-sS --max-time 20 -X "$method" -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json')
    [[ -n $data ]] && args+=(-H 'Content-Type: application/json' --data "$data")
    curl "${args[@]}" "$BASE$path"
}

# Удаляем старые тестовые inbound'ы
for id in $(api GET /panel/api/inbounds/list | jq -r '.obj[]? | select(.remark | startswith("test-")) | .id'); do
    api POST "/panel/api/inbounds/del/$id" >/dev/null
done

keys=$(api GET /panel/api/server/getNewX25519Cert)
PRIV=$(jq -r '.obj.privateKey' <<<"$keys")
PBK=$(jq -r '.obj.publicKey' <<<"$keys")
[[ -n $PRIV && $PRIV != null ]] || die "Не удалось получить ключи: $keys"

enc=$(api GET /panel/api/server/getNewVlessEnc)
# Предпочитаем ML-KEM (как в рабочем конфиге Happ), иначе первый вариант
VENC=$(jq -r '[.obj.auths[]? | select((.label // "") | test("ML-KEM|mlkem"; "i"))][0].encryption // .obj.auths[0].encryption // empty' <<<"$enc")
VDEC=$(jq -r '[.obj.auths[]? | select((.label // "") | test("ML-KEM|mlkem"; "i"))][0].decryption // .obj.auths[0].decryption // empty' <<<"$enc")

# add <remark> <port> <network> <flow> <decryption> <encryption>
add() {
    local remark=$1 port=$2 net=$3 flow=$4 dec=$5 encr=$6
    local id sid path payload resp
    id=$(cat /proc/sys/kernel/random/uuid)
    sid=$(openssl rand -hex 8)
    path="/$(openssl rand -hex 6)"
    payload=$(jq -nc --arg remark "$remark" --argjson port "$port" --arg net "$net" \
        --arg id "$id" --arg flow "$flow" --arg email "$remark-$(openssl rand -hex 3)" \
        --arg dec "$dec" --arg encr "$encr" --arg sni "$SNI" --arg priv "$PRIV" \
        --arg pbk "$PBK" --arg sid "$sid" --arg path "$path" '
    {
      enable: true, remark: $remark, listen: "", port: $port, protocol: "vless",
      expiryTime: 0, total: 0, up: 0, down: 0,
      settings: {
        clients: [{ id: $id, flow: $flow, email: $email, limitIp: 0, totalGB: 0,
                    expiryTime: 0, enable: true, comment: "", reset: 0 }],
        decryption: (if $dec == "" then "none" else $dec end),
        encryption: (if $encr == "" then "none" else $encr end)
      } + (if $dec == "" then { fallbacks: [] } else {} end),
      streamSettings: ({
        network: $net, security: "reality", externalProxy: [],
        realitySettings: {
          show: false, xver: 0, target: ($sni + ":443"), serverNames: [$sni],
          privateKey: $priv, minClientVer: "", maxClientVer: "", maxTimediff: 0,
          shortIds: [$sid],
          settings: { publicKey: $pbk, fingerprint: "chrome", serverName: "", spiderX: "/" }
        }
      } + (if $net == "xhttp"
           then { xhttpSettings: { path: $path, host: "", mode: "auto" } }
           else { tcpSettings: { acceptProxyProtocol: false, header: { type: "none" } } } end)),
      sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false, routeOnly: false }
    }')
    resp=$(api POST /panel/api/inbounds/add "$payload")
    if ! jq -e '.success' >/dev/null <<<"$resp"; then
        echo "[$remark] не создан: $resp" >&2
        return
    fi
    # Одна битая настройка роняет весь Xray (и основной inbound) — проверяем сразу
    local ok=0 i
    for i in $(seq 1 20); do
        if ss -Hltn "sport = :443" | grep -q . && ss -Hltn "sport = :$port" | grep -q .; then ok=1; break; fi
        sleep 1
    done
    if [[ $ok != 1 ]]; then
        echo "[$remark] Xray не принял конфиг, удаляю:" >&2
        journalctl -u x-ui -n 30 --no-pager | grep -m1 'Failed to start' >&2 || true
        local bad
        for bad in $(api GET /panel/api/inbounds/list | jq -r --arg r "$remark" '.obj[]? | select(.remark==$r) | .id'); do
            api POST "/panel/api/inbounds/del/$bad" >/dev/null
        done
        systemctl restart x-ui
        sleep 5
        return
    fi
    local q="type=$net&security=reality&pbk=$PBK&fp=chrome&sni=$SNI&sid=$sid&spx=%2F"
    [[ -n $flow ]] && q+="&flow=$flow"
    q+="&encryption=${encr:-none}"
    [[ $net == xhttp ]] && q+="&path=$(sed 's#/#%2F#g' <<<"$path")&mode=auto"
    LINKS+=("$remark|vless://$id@$PUBLIC_IP:$port?$q#$remark")
}

LINKS=()
add test-A-vision    8443  tcp   xtls-rprx-vision "" ""
add test-B-xhttp     9443  xhttp ""               "" ""
[[ -n $VDEC && -n $VENC ]] \
    && add test-C-vlessenc 10443 tcp "" "$VDEC" "$VENC" \
    || echo "VLESS encryption не поддерживается этой версией панели, вариант C пропущен" >&2

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    for p in 8443 9443 10443; do ufw allow "$p/tcp" >/dev/null; done
fi

echo
echo "SNI для всех вариантов: $SNI"
echo "  A — TCP + Reality + Vision (как основной, только другой SNI)"
echo "  B — XHTTP + Reality"
echo "  C — TCP + Reality + VLESS encryption ML-KEM (как ваш рабочий конфиг)"
echo
for l in "${LINKS[@]}"; do
    echo "=== ${l%%|*}"
    echo "${l#*|}"
    echo
done
echo "Тестовые inbound'ы (test-*) можно удалить в панели, раздел Inbounds."
