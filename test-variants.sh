#!/bin/bash
#
# test-variants.sh — создаёт в 3x-ui несколько тестовых inbound'ов с разными
# настройками маскировки и печатает ссылки, чтобы понять, какой вариант
# проходит через DPI провайдера. Запускать на сервере №1 после entry-server.sh.
#
#   SNI=firstvds.ru bash test-variants.sh
#
# Повторный запуск пересоздаёт тестовые inbound'ы (remark начинается с test-).
#
# Варианты:
#   A  8443/tcp   VLESS + TCP + Reality + Vision
#   B  9443/tcp   VLESS + XHTTP + Reality
#   C  10443/tcp  VLESS + TCP + Reality + VLESS encryption (ML-KEM)
#   D  8388/tcp+udp  Shadowsocks-2022
#   E  4443/udp   Hysteria2 (QUIC)
#   F  51820/udp  AmneziaWG (WireGuard с обфускацией против DPI)

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
# После SUB_DOMAIN панель работает по HTTPS
scheme=http
$XUI_DIR/x-ui setting -getCert true 2>/dev/null | grep 'cert:' | awk -F': ' '{print $2}' | grep -q '[^[:space:]]' && scheme=https
BASE="$scheme://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH"
PUBLIC_IP=$(curl -4 -fsS --max-time 5 --interface "$(ip -4 route get 1.1.1.1 | grep -oP 'src \K\S+')" https://ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]') || true
[[ -n $PUBLIC_IP ]] || PUBLIC_IP=$(ip -4 -o addr show scope global | awk '{split($4,a,"/"); print a[1]; exit}')

api() {
    local method=$1 path=$2 data=${3:-}
    local args=(-sSk --max-time 20 -X "$method" -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json')
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
      settings: ({
        clients: [{ id: $id, flow: $flow, email: $email, limitIp: 0, totalGB: 0,
                    expiryTime: 0, enable: true, comment: "", reset: 0 }],
        decryption: (if $dec == "" then "none" else $dec end),
        encryption: (if $encr == "" then "none" else $encr end)
      } + (if $dec == "" then { fallbacks: [] } else {} end)),
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

# add_raw <remark> <port> <tcp|udp> <payload-json>
# Для протоколов, ссылки на которые проще взять в панели (QR у клиента).
add_raw() {
    local remark=$1 port=$2 l4=$3 payload=$4 resp ok=0 i bad
    resp=$(api POST /panel/api/inbounds/add "$payload")
    if ! jq -e '.success' >/dev/null <<<"$resp"; then
        echo "[$remark] не создан: $resp" >&2
        return
    fi
    for i in $(seq 1 20); do
        if ss -Hltn "sport = :443" | grep -q . && ss -Hl${l4:0:1}n "sport = :$port" | grep -q .; then ok=1; break; fi
        sleep 1
    done
    if [[ $ok != 1 ]]; then
        echo "[$remark] не запустился, удаляю:" >&2
        journalctl -u x-ui -n 40 --no-pager | grep -iE 'Failed to start|error' | tail -2 >&2 || true
        for bad in $(api GET /panel/api/inbounds/list | jq -r --arg r "$remark" '.obj[]? | select(.remark==$r) | .id'); do
            api POST "/panel/api/inbounds/del/$bad" >/dev/null
        done
        systemctl restart x-ui
        sleep 5
        return
    fi
    LINKS+=("$remark|ссылку/QR возьмите в панели: Inbounds → $remark → клиент → QR")
}

client_base() {  # общие поля клиента 3x-ui
    jq -nc --arg email "$1" '{email: $email, limitIp: 0, totalGB: 0, expiryTime: 0, enable: true,
        tgId: 0, subId: "", comment: "", reset: 0}'
}

inbound_base() {  # <remark> <port> <protocol>
    jq -nc --arg r "$1" --argjson p "$2" --arg proto "$3" '{enable: true, remark: $r, listen: "", port: $p,
        protocol: $proto, expiryTime: 0, total: 0, up: 0, down: 0,
        sniffing: {enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false, routeOnly: false}}'
}

wg_keypair() {  # печатает "private public" (Curve25519, base64, как у WireGuard)
    local k
    k=$(openssl genpkey -algorithm X25519 2>/dev/null)
    echo "$(openssl pkey -outform DER <<<"$k" | tail -c 32 | base64) $(openssl pkey -pubout -outform DER <<<"$k" | tail -c 32 | base64)"
}

rnd() { shuf -i "$1-$2" -n 1; }

# Порт internal/amneziawg.GenerateObfuscation31 из 3x-ui v3.8.5
awg_obfuscation() {
    local jmin s1 s2 band lo=5 hmax=2147483647 h=() i cp rk rkh rj rt ka ha
    jmin=$(rnd 40 89)
    s1=$(rnd 15 150); s2=$(rnd 15 150)
    while (( s1 + 56 == s2 )); do s2=$(rnd 15 150); done
    band=$(( (hmax - lo + 1) / 4 ))
    for i in 0 1 2 3; do h+=("$(rnd $((lo + i * band)) $((lo + i * band + band - 1)))"); done
    cp=$(rnd 8 24); rk=$(rnd 100 120); rkh=$((rk + $(rnd 10 40))); rj=$((rkh + $(rnd 30 60)))
    rt=$(rnd 3 6); ka=$(rnd 8 12); ha=$(rnd 15 25)
    jq -nc --argjson jc "$(rnd 3 6)" --argjson jmin "$jmin" --argjson jmax "$((jmin + $(rnd 50 250)))" \
        --argjson s1 "$s1" --argjson s2 "$s2" --argjson s3 "$(rnd 12 55)" --argjson s4 "$(rnd 12 27)" \
        --arg h1 "${h[0]}" --arg h2 "${h[1]}" --arg h3 "${h[2]}" --arg h4 "${h[3]}" \
        --arg i1 "<r $(rnd 32 256)>" --arg hpk "$(openssl rand -base64 32)" \
        --arg cpa "$cp-$((cp + $(rnd 8 40)))" --arg rka "$rk-$rkh" --arg rja "$rj-$((rj + $(rnd 30 90)))" \
        --arg rto "$rt-$((rt + $(rnd 1 4)))" --arg kat "$ka-$((ka + $(rnd 2 8)))" --arg mha "$ha-$((ha + $(rnd 5 25)))" '
        {jc: $jc, jmin: $jmin, jmax: $jmax, s1: $s1, s2: $s2, s3: $s3, s4: $s4,
         h1: $h1, h2: $h2, h3: $h3, h4: $h4, i1: $i1, i2: "", i3: "", i4: "", i5: "",
         headerProtectionKey: $hpk, contentPaddingAddition: $cpa,
         rekeyAfterTime: $rka, rekeyTimeout: $rto, rejectAfterTime: $rja,
         keepaliveTimeout: $kat, maxHandshakeAttempts: $mha,
         randomTrailers: true, disableCookies: true}'
}

add_ss() {
    local r=test-D-shadowsocks port=8388
    local payload
    payload=$(jq -c --argjson c "$(client_base "$r-$(openssl rand -hex 3)")" \
        --arg sp "$(openssl rand -base64 32)" --arg cp "$(openssl rand -base64 32)" '
        . + {settings: {method: "2022-blake3-aes-256-gcm", password: $sp, network: "tcp,udp",
                        clients: [$c + {method: "", password: $cp}], ivCheck: false},
             streamSettings: {network: "tcp", tcpSettings: {header: {type: "none"}}, security: "none"}}' \
        <<<"$(inbound_base $r $port shadowsocks)")
    add_raw $r $port tcp "$payload"
}

add_hy2() {
    local r=test-E-hysteria2 port=4443 dir=/etc/l2tp-exit/hy2 cert key sni
    # Если есть сертификат от SUB_DOMAIN — берём его, иначе самоподписанный
    # (тогда в клиенте нужно разрешить insecure / «небезопасный сертификат»)
    cert=$(ls /root/cert/*/fullchain.pem 2>/dev/null | head -n1)
    if [[ -n $cert ]]; then
        key=${cert%/fullchain.pem}/privkey.pem
        sni=$(basename "$(dirname "$cert")")
    else
        mkdir -p $dir
        cert=$dir/cert.pem; key=$dir/key.pem; sni=$SNI
        [[ -f $cert ]] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
            -subj "/CN=$sni" -keyout $key -out $cert >/dev/null 2>&1
        HY2_SELF_SIGNED=1
    fi
    local payload
    payload=$(jq -c --argjson c "$(client_base "$r-$(openssl rand -hex 3)")" --arg auth "$(openssl rand -hex 12)" \
        --arg cert "$cert" --arg key "$key" --arg sni "$sni" '
        . + {settings: {version: 2, clients: [$c + {auth: $auth}]},
             streamSettings: {network: "tcp", tcpSettings: {}, security: "tls",
               tlsSettings: {serverName: $sni, minVersion: "1.2", maxVersion: "1.3", cipherSuites: "",
                 rejectUnknownSni: false, disableSystemRoot: false, enableSessionResumption: false,
                 certificates: [{certificateFile: $cert, keyFile: $key, oneTimeLoading: false,
                                 usage: "encipherment", buildChain: false}],
                 alpn: ["h3"], echServerKeys: "", settings: {fingerprint: "chrome", echConfigList: ""}}}}' \
        <<<"$(inbound_base $r $port hysteria)")
    add_raw $r $port udp "$payload"
}

add_awg() {
    local r=test-F-amneziawg port=51820 srv cli
    read -r -a srv <<<"$(wg_keypair)"
    read -r -a cli <<<"$(wg_keypair)"
    local payload
    payload=$(jq -c --argjson c "$(client_base "$r-$(openssl rand -hex 3)")" --argjson obf "$(awg_obfuscation)" \
        --arg spriv "${srv[0]}" --arg spub "${srv[1]}" --arg cpriv "${cli[0]}" --arg cpub "${cli[1]}" \
        --arg psk "$(openssl rand -base64 32)" '
        . + {settings: {
               server: ({privateKey: $spriv, publicKey: $spub, subnetIp: "10.8.1.0", subnetCidr: 24,
                         primaryDns: "1.1.1.1", secondaryDns: "8.8.8.8", externalInterface: "",
                         ipv6Enabled: false, ipv6Subnet: "", ipv6ExternalInterface: ""} + $obf),
               clients: [$c + {privateKey: $cpriv, publicKey: $cpub, preSharedKey: $psk,
                               allowedIPs: ["10.8.1.2/32"], keepAlive: 25, forwardedPorts: ""}]}}' \
        <<<"$(inbound_base $r $port amneziawg)")
    add_raw $r $port udp "$payload"
}

LINKS=()
HY2_SELF_SIGNED=0
add test-A-vision    8443  tcp   xtls-rprx-vision "" ""
add test-B-xhttp     9443  xhttp ""               "" ""
[[ -n $VDEC && -n $VENC ]] \
    && add test-C-vlessenc 10443 tcp "" "$VDEC" "$VENC" \
    || echo "VLESS encryption не поддерживается этой версией панели, вариант C пропущен" >&2
add_ss
add_hy2
add_awg

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    for p in 8443 9443 10443 8388; do ufw allow "$p/tcp" >/dev/null; done
    for p in 8388 4443 51820; do ufw allow "$p/udp" >/dev/null; done
fi

echo
echo "SNI для вариантов A–C: $SNI"
echo "  A — VLESS TCP + Reality + Vision        (Happ)"
echo "  B — VLESS XHTTP + Reality               (Happ)"
echo "  C — VLESS TCP + Reality + VLESS encryption (Happ)"
echo "  D — Shadowsocks-2022, 8388 tcp/udp      (Happ)"
echo "  E — Hysteria2, 4443/udp                 (Happ)"
echo "  F — AmneziaWG, 51820/udp                (приложение AmneziaVPN или AmneziaWG)"
[[ $HY2_SELF_SIGNED == 1 ]] && echo "  Для E сертификат самоподписанный: в клиенте включите «Allow insecure»."
echo
for l in "${LINKS[@]}"; do
    echo "=== ${l%%|*}"
    echo "${l#*|}"
    echo
done
echo "Тестовые inbound'ы (test-*) можно удалить в панели, раздел Inbounds."
