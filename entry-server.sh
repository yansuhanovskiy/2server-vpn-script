#!/bin/bash
#
# entry-server.sh — сервер №1 (входной узел, принимает клиентов).
#
# 1. Поднимает L2TP/IPsec клиент (strongSwan swanctl + xl2tpd) до сервера №2,
#    настроенного через exit-server.sh / hwdsl2/setup-ipsec-vpn.
# 2. Настраивает policy routing: весь исходящий трафик сервера идёт через
#    туннель, а ответы на входящие соединения (SSH, клиенты, панель) — напрямую.
#    Туннель поддерживается systemd-сервисом l2tp-exit (автопереподключение).
# 3. Ставит 3x-ui, создаёт inbound VLESS + Reality и печатает данные доступа.
#
# Обязательные переменные (их печатает exit-server.sh):
#   VPN_SERVER_IP  VPN_IPSEC_PSK  VPN_USER  VPN_PASSWORD
#
# Необязательные:
#   INBOUND_PORT=443                 порт VLESS Reality
#   REALITY_SNI=www.microsoft.com    домен для маскировки Reality
#   INBOUND_REMARK=vless-reality     имя inbound в панели
#   XUI_USERNAME / XUI_PASSWORD      логин/пароль панели (иначе случайные)
#   XUI_PANEL_PORT                   порт панели (иначе случайный)
#   XUI_WEB_BASE_PATH                секретный путь панели (иначе случайный)
#   XUI_SSL_MODE=none                none | ip | domain (см. install.sh 3x-ui)
#   KILL_SWITCH=1                    при падении туннеля не выпускать трафик напрямую
#   DISABLE_IPV6=1                   выключить IPv6 (туннель только IPv4, иначе утечки)
#   SET_DNS=1                        резолвер 1.1.1.1/8.8.8.8 (запросы идут через туннель)
#
# Повторный запуск безопасен: конфиги перезаписываются, существующий inbound
# и учётные данные панели переиспользуются.

set -euo pipefail

CONN=l2tp-exit
CONF_DIR=/etc/l2tp-exit
HELPER=/usr/local/sbin/l2tp-exit
XUI_DIR=/usr/local/x-ui
ACCESS_FILE=/root/vpn-access.txt
SCRIPT_VERSION=3

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; blue='\033[0;34m'; plain='\033[0m'
log()  { echo -e "${green}==>${plain} $*"; }
warn() { echo -e "${yellow}WARN:${plain} $*" >&2; }
die()  { echo -e "${red}ERROR:${plain} $*" >&2; exit 1; }

rand() {
    local s
    s=$(openssl rand -base64 96 | tr -dc 'A-Za-z0-9')
    printf '%s' "${s:0:$1}"
}

# ---------------------------------------------------------------------------
# Проверки и параметры
# ---------------------------------------------------------------------------

log "entry-server.sh, версия $SCRIPT_VERSION"
[[ $EUID -eq 0 ]] || die "Запустите от root."
[[ -f /etc/debian_version ]] || die "Поддерживаются только Debian/Ubuntu."

for v in VPN_SERVER_IP VPN_IPSEC_PSK VPN_USER VPN_PASSWORD; do
    [[ -n ${!v:-} ]] || die "Не задана переменная $v. Возьмите команду из вывода exit-server.sh."
done
[[ $VPN_SERVER_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VPN_SERVER_IP должен быть IPv4-адресом."
for v in "$VPN_IPSEC_PSK" "$VPN_USER" "$VPN_PASSWORD"; do
    [[ $v =~ [\\\"\'] ]] && die "Логин/пароль/PSK не должны содержать символы \\ \" '"
done

INBOUND_PORT=${INBOUND_PORT:-443}
REALITY_SNI=${REALITY_SNI:-www.microsoft.com}
INBOUND_REMARK=${INBOUND_REMARK:-vless-reality}
XUI_SSL_MODE=${XUI_SSL_MODE:-none}
KILL_SWITCH=${KILL_SWITCH:-1}
DISABLE_IPV6=${DISABLE_IPV6:-1}
SET_DNS=${SET_DNS:-1}

mkdir -p "$CONF_DIR"
chmod 700 "$CONF_DIR"

# Учётные данные панели: env > сохранённые с прошлого запуска > случайные
if [[ -f $CONF_DIR/xui.env ]]; then
    # shellcheck disable=SC1091
    { saved_user=$(. "$CONF_DIR/xui.env"; echo "$XUI_USERNAME")
      saved_pass=$(. "$CONF_DIR/xui.env"; echo "$XUI_PASSWORD")
      saved_port=$(. "$CONF_DIR/xui.env"; echo "$XUI_PANEL_PORT")
      saved_path=$(. "$CONF_DIR/xui.env"; echo "$XUI_WEB_BASE_PATH"); }
fi
XUI_USERNAME=${XUI_USERNAME:-${saved_user:-$(rand 10)}}
XUI_PASSWORD=${XUI_PASSWORD:-${saved_pass:-$(rand 16)}}
XUI_WEB_BASE_PATH=${XUI_WEB_BASE_PATH:-${saved_path:-$(rand 18)}}
XUI_WEB_BASE_PATH=${XUI_WEB_BASE_PATH#/}; XUI_WEB_BASE_PATH=${XUI_WEB_BASE_PATH%/}
if [[ -z ${XUI_PANEL_PORT:-} ]]; then
    XUI_PANEL_PORT=${saved_port:-}
    while [[ -z $XUI_PANEL_PORT || $XUI_PANEL_PORT == "$INBOUND_PORT" ]]; do
        XUI_PANEL_PORT=$(shuf -i 20000-60000 -n 1)
    done
fi

# ---------------------------------------------------------------------------
# Сеть до изменений
# ---------------------------------------------------------------------------

default_line=$(ip -4 route show default table main | head -n1)
[[ -n $default_line ]] || die "Нет маршрута по умолчанию."
WAN_DEV=$(awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$default_line")
WAN_IP=$(ip -4 -o addr show dev "$WAN_DEV" scope global | awk '{split($4,a,"/"); print a[1]; exit}')
[[ -n $WAN_IP ]] || die "Не удалось определить IPv4 адрес на $WAN_DEV."

PUBLIC_IP=""
for u in https://ipv4.icanhazip.com https://api4.ipify.org https://4.ident.me; do
    PUBLIC_IP=$(curl -4 -fsS --max-time 5 --interface "$WAN_IP" "$u" 2>/dev/null | tr -d '[:space:]') || true
    [[ $PUBLIC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && break
    PUBLIC_IP=""
done
[[ -n $PUBLIC_IP ]] || { warn "Публичный IP не определён, использую $WAN_IP"; PUBLIC_IP=$WAN_IP; }
log "Интерфейс: $WAN_DEV, локальный IP: $WAN_IP, публичный IP: $PUBLIC_IP"

# ---------------------------------------------------------------------------
# Пакеты
# ---------------------------------------------------------------------------

log "Устанавливаю пакеты ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# Старый stroke-стек (ipsec.conf/starter) конфликтует с charon-systemd за порты 500/4500
if dpkg -s strongswan-starter >/dev/null 2>&1; then
    warn "Удаляю strongswan-starter (используется swanctl/charon-systemd)."
    systemctl disable --now strongswan-starter >/dev/null 2>&1 || true
    apt-get purge -y -qq strongswan-starter strongswan >/dev/null || true
fi
apt-get install -y -qq \
    charon-systemd strongswan-swanctl libstrongswan-standard-plugins \
    xl2tpd ppp iproute2 curl jq openssl qrencode ca-certificates >/dev/null

SWAN_UNIT=""
for u in strongswan.service strongswan-swanctl.service; do
    if systemctl cat "$u" >/dev/null 2>&1; then SWAN_UNIT=$u; break; fi
done
[[ -n $SWAN_UNIT ]] || die "Не найден systemd-юнит strongSwan (charon-systemd)."

# ---------------------------------------------------------------------------
# IPsec (swanctl) + L2TP (xl2tpd) + PPP
# ---------------------------------------------------------------------------

log "Настраиваю IPsec/L2TP клиент до $VPN_SERVER_IP ..."
umask 077

# Алгоритмы подобраны под Libreswan-конфиг hwdsl2 (ike=aes256-sha2;modp2048,...)
cat > /etc/swanctl/conf.d/$CONN.conf <<EOF
connections {
    $CONN {
        version = 1
        remote_addrs = $VPN_SERVER_IP
        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048
        dpd_delay = 30s
        local {
            auth = psk
        }
        remote {
            auth = psk
        }
        children {
            $CONN {
                mode = transport
                local_ts = dynamic[udp/1701]
                remote_ts = dynamic[udp/1701]
                esp_proposals = aes256-sha256,aes128-sha1,aes256-sha1
                dpd_action = restart
                start_action = none
            }
        }
    }
}

secrets {
    ike-$CONN {
        secret = "$VPN_IPSEC_PSK"
    }
}
EOF
chmod 600 /etc/swanctl/conf.d/$CONN.conf

[[ -f /etc/xl2tpd/xl2tpd.conf && ! -f /etc/xl2tpd/xl2tpd.conf.orig ]] \
    && cp /etc/xl2tpd/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf.orig
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[lac $CONN]
lns = $VPN_SERVER_IP
ppp debug = no
pppoptfile = /etc/ppp/options.$CONN
length bit = yes
EOF

# Маршруты pppd не трогает (nodefaultroute) — ими управляет $HELPER.
# ipparam позволяет хукам ip-up/ip-down узнать «свой» интерфейс.
cat > /etc/ppp/options.$CONN <<EOF
ipcp-accept-local
ipcp-accept-remote
refuse-eap
require-chap
noccp
noauth
mtu 1280
mru 1280
noipdefault
nodefaultroute
connect-delay 5000
lcp-echo-interval 20
lcp-echo-failure 4
ipparam $CONN
name "$VPN_USER"
password "$VPN_PASSWORD"
EOF
chmod 600 /etc/ppp/options.$CONN

umask 022

cat > $CONF_DIR/$CONN.env <<EOF
VPN_SERVER_IP=$VPN_SERVER_IP
KILL_SWITCH=$KILL_SWITCH
SWAN_UNIT=$SWAN_UNIT
EOF

cat > /etc/ppp/ip-up.d/$CONN <<'EOF'
#!/bin/sh
[ "$PPP_IPPARAM" = "l2tp-exit" ] || exit 0
echo "$PPP_IFACE" > /run/l2tp-exit.iface
ip route replace default dev "$PPP_IFACE" metric 50 table 202
ip route flush cache
EOF
cat > /etc/ppp/ip-down.d/$CONN <<'EOF'
#!/bin/sh
[ "$PPP_IPPARAM" = "l2tp-exit" ] || exit 0
rm -f /run/l2tp-exit.iface
ip route del default dev "$PPP_IFACE" metric 50 table 202 2>/dev/null || true
EOF
chmod 755 /etc/ppp/ip-up.d/$CONN /etc/ppp/ip-down.d/$CONN

# ---------------------------------------------------------------------------
# Хелпер: маршрутизация + watchdog
# ---------------------------------------------------------------------------
#
# Таблица 202 (tunnel): default через ppp, при KILL_SWITCH=1 ещё unreachable.
# Прямой трафик смотрит в НЕИЗМЕНЁННУЮ таблицу main (исходная маршрутизация
# сервера), поэтому SSH идёт ровно тем путём, что и до установки.
#   pref 999   TCP с исходящим портом sshd -> main (SSH, даже на нестандартном порту)
#   pref 1000  to VPN_SERVER_IP            -> main (IKE/ESP/L2TP идут напрямую)
#   pref 1001  from <IP на WAN_DEV>        -> main (ответы клиентам, SSH, панель)
#   pref 1002  main без default            -> подсети провайдера, peer ppp и т.д.
#   pref 1003  всё остальное               -> 202  (в туннель)
# `l2tp-exit down` удаляет правила и полностью откатывает схему.

cat > $HELPER <<'HELPER_EOF'
#!/bin/bash
set -u
CONN=l2tp-exit
T_TUN=202
CTL=/var/run/xl2tpd/l2tp-control
IFACE_FILE=/run/l2tp-exit.iface
SIG_FILE=/run/l2tp-exit.routes
. /etc/l2tp-exit/l2tp-exit.env

log() { echo "l2tp-exit: $*"; }

flush_rules() {
    local p
    for p in 999 1000 1001 1002 1003; do
        while ip -4 rule del pref $p 2>/dev/null; do :; done
    done
}

ssh_ports() {
    { sshd -T 2>/dev/null | awk '$1=="port"{print $2}'; echo 22; } | sort -u
}

apply_routes() {
    local line dev ips sig ip port
    line=$(ip -4 route show default table main | head -n1)
    # Без default в main правила отправили бы ответы SSH в kill switch
    [ -n "$line" ] || { log "нет default-маршрута в main, правила не применяю"; flush_rules; return 1; }
    dev=$(awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$line")
    ips=$(ip -4 -o addr show dev "$dev" scope global | awk '{split($4,a,"/"); print a[1]}' | tr '\n' ' ')
    sig="$dev|$ips|$(ssh_ports | tr '\n' ' ')|$VPN_SERVER_IP|$KILL_SWITCH"
    if [ "$sig" = "$(cat $SIG_FILE 2>/dev/null)" ] && ip -4 rule show pref 1003 | grep -q .; then
        return 0
    fi
    log "применяю маршруты ($sig)"
    flush_rules
    for port in $(ssh_ports); do
        ip -4 rule add pref 999 ipproto tcp sport "$port" lookup main 2>/dev/null
    done
    ip -4 rule add pref 1000 to "$VPN_SERVER_IP" lookup main
    for ip in $ips; do
        ip -4 rule add pref 1001 from "$ip" lookup main
    done
    ip -4 rule add pref 1002 lookup main suppress_prefixlength 0
    ip -4 rule add pref 1003 lookup $T_TUN
    if [ "$KILL_SWITCH" = "1" ]; then
        ip route replace unreachable default metric 4000 table $T_TUN
    else
        ip route del unreachable default metric 4000 table $T_TUN 2>/dev/null
    fi
    # ppp мог подняться раньше, чем появились правила
    if [ -f $IFACE_FILE ] && ip link show "$(cat $IFACE_FILE)" >/dev/null 2>&1; then
        ip route replace default dev "$(cat $IFACE_FILE)" metric 50 table $T_TUN
    fi
    ip route flush cache
    echo "$sig" > $SIG_FILE
}

remove_routes() {
    flush_rules
    ip route flush table 201 2>/dev/null   # от старых версий скрипта
    ip route flush table $T_TUN 2>/dev/null
    rm -f $SIG_FILE
    ip route flush cache
}

is_up() {
    local ifc
    [ -f $IFACE_FILE ] || return 1
    ifc=$(cat $IFACE_FILE)
    ip -4 addr show dev "$ifc" 2>/dev/null | grep -q 'inet '
}

ctl() {
    [ -p $CTL ] || return 1
    timeout 5 sh -c "echo '$1' > $CTL"
}

connect() {
    local i
    if ! swanctl --list-sas --ike $CONN 2>/dev/null | grep -q INSTALLED; then
        swanctl --terminate --ike $CONN >/dev/null 2>&1
        swanctl --initiate --child $CONN --timeout 30 >/dev/null 2>&1 \
            || { log "IPsec не поднялся"; return 1; }
        log "IPsec SA установлена"
    fi
    ctl "d $CONN"
    sleep 1
    ctl "c $CONN" || { log "xl2tpd недоступен"; return 1; }
    for i in $(seq 1 30); do
        is_up && { log "PPP поднят: $(cat $IFACE_FILE)"; return 0; }
        sleep 1
    done
    log "PPP не поднялся"
    return 1
}

watch() {
    local fails=0
    swanctl --load-all --noprompt >/dev/null 2>&1
    while :; do
        apply_routes
        if is_up; then
            fails=0
        else
            log "туннель не активен, подключаюсь"
            if ! connect; then
                fails=$((fails + 1))
                if [ $fails -ge 3 ]; then
                    log "перезапускаю $SWAN_UNIT и xl2tpd"
                    systemctl restart "$SWAN_UNIT" xl2tpd
                    sleep 3
                    swanctl --load-all --noprompt >/dev/null 2>&1
                    fails=0
                fi
            fi
        fi
        sleep 15
    done
}

status() {
    echo "--- IPsec"; swanctl --list-sas --ike $CONN 2>/dev/null
    echo "--- PPP";   if is_up; then ip -4 addr show dev "$(cat $IFACE_FILE)"; else echo "down"; fi
    echo "--- rules"; ip -4 rule show | grep -E '^(999|100[0-3]):'
    echo "--- table $T_TUN";    ip route show table $T_TUN
    echo "--- exit IP"; curl -4 -s --max-time 8 https://ipv4.icanhazip.com || echo "недоступно"
}

case "${1:-}" in
    routes) apply_routes ;;
    watch)  watch ;;
    status) status ;;
    down)
        systemctl stop l2tp-exit 2>/dev/null
        ctl "d $CONN"
        swanctl --terminate --ike $CONN >/dev/null 2>&1
        remove_routes
        log "туннель остановлен, маршрутизация возвращена к исходной"
        ;;
    *) echo "usage: $0 {status|down|routes|watch}"; exit 1 ;;
esac
HELPER_EOF
chmod 755 $HELPER

cat > /etc/systemd/system/$CONN.service <<EOF
[Unit]
Description=L2TP/IPsec uplink to exit server $VPN_SERVER_IP
Wants=network-online.target $SWAN_UNIT xl2tpd.service
After=network-online.target $SWAN_UNIT xl2tpd.service

[Service]
ExecStart=$HELPER watch
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# sysctl: IPv6 и rp_filter
# ---------------------------------------------------------------------------

{
    echo "net.ipv4.conf.all.rp_filter = 2"
    echo "net.ipv4.conf.default.rp_filter = 2"
    if [[ $DISABLE_IPV6 == 1 ]]; then
        # L2TP-туннель только IPv4: без этого Xray уходил бы в IPv6 напрямую
        echo "net.ipv6.conf.all.disable_ipv6 = 1"
        echo "net.ipv6.conf.default.disable_ipv6 = 1"
    fi
} > /etc/sysctl.d/90-$CONN.conf
sysctl -q -p /etc/sysctl.d/90-$CONN.conf >/dev/null || warn "Не все sysctl применились"

# ---------------------------------------------------------------------------
# Запуск туннеля
# ---------------------------------------------------------------------------

log "Запускаю туннель ..."
systemctl stop $CONN >/dev/null 2>&1 || true
rm -f /run/l2tp-exit.iface
mkdir -p /var/run/xl2tpd
systemctl daemon-reload
systemctl enable "$SWAN_UNIT" xl2tpd >/dev/null 2>&1
systemctl restart "$SWAN_UNIT"
systemctl restart xl2tpd
sleep 2
swanctl --load-all --noprompt >/dev/null 2>&1 || true
rm -f /run/l2tp-exit.routes

# Страховка: если связь с сервером потеряется и скрипт не дойдёт до конца
# (например, умрёт вместе с SSH-сессией), через 5 минут всё откатится.
systemctl stop $CONN-rollback.timer $CONN-rollback.service >/dev/null 2>&1 || true
systemctl reset-failed $CONN-rollback.service >/dev/null 2>&1 || true
systemd-run --quiet --unit=$CONN-rollback --on-active=300 \
    /bin/sh -c "systemctl disable $CONN; $HELPER down" \
    || warn "Не удалось поставить таймер отката"

systemctl enable $CONN >/dev/null 2>&1
systemctl restart $CONN

up=0
for _ in $(seq 1 90); do
    if [[ -f /run/l2tp-exit.iface ]] && ip -4 addr show dev "$(cat /run/l2tp-exit.iface)" 2>/dev/null | grep -q 'inet '; then
        up=1; break
    fi
    sleep 1
done

if [[ $up != 1 ]]; then
    echo
    journalctl -u $CONN -n 30 --no-pager || true
    journalctl -u "$SWAN_UNIT" -n 20 --no-pager || true
    journalctl -u xl2tpd -n 20 --no-pager || true
    systemctl disable $CONN >/dev/null 2>&1 || true
    $HELPER down || true
    systemctl stop $CONN-rollback.timer >/dev/null 2>&1 || true
    die "Туннель не поднялся за 90 секунд. Маршрутизация откатена. Проверьте данные доступа и что на сервере №2 открыты UDP 500/4500."
fi

# Прямой путь (им ходят ответы на SSH и клиентам) должен работать
DIRECT_IP=$(curl -4 -fsS --max-time 10 --interface "$WAN_IP" https://ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]') || DIRECT_IP=""
if [[ -z $DIRECT_IP ]]; then
    systemctl disable $CONN >/dev/null 2>&1 || true
    $HELPER down || true
    systemctl stop $CONN-rollback.timer >/dev/null 2>&1 || true
    ip -4 route show table main
    die "Прямой маршрут через $WAN_DEV не работает при включённом туннеле. Всё откатил, пришлите вывод выше."
fi
systemctl stop $CONN-rollback.timer >/dev/null 2>&1 || true
log "Прямой маршрут работает, таймер отката снят"

EXIT_IP=$(curl -4 -fsS --max-time 10 https://ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]') || EXIT_IP=""
if [[ -z $EXIT_IP ]]; then
    warn "Туннель поднят, но внешний IP через него не получен."
elif [[ $EXIT_IP == "$PUBLIC_IP" ]]; then
    warn "Внешний IP совпадает с IP этого сервера ($EXIT_IP) — трафик идёт не через туннель!"
else
    log "Туннель работает, внешний IP: $EXIT_IP"
fi

if [[ $SET_DNS == 1 ]]; then
    # Статический resolv.conf: DNS провайдера может не отвечать на запросы с IP
    # выходного сервера и/или подменять ответы. Запросы к 1.1.1.1 идут через туннель.
    if [[ ! -e /etc/resolv.conf.l2tp-exit.bak ]]; then
        cp -P /etc/resolv.conf /etc/resolv.conf.l2tp-exit.bak 2>/dev/null || true
    fi
    rm -f /etc/resolv.conf
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:2\n' > /etc/resolv.conf
fi

# ---------------------------------------------------------------------------
# 3x-ui
# ---------------------------------------------------------------------------

if [[ ! -x $XUI_DIR/x-ui ]]; then
    log "Устанавливаю 3x-ui ..."
    curl -fsSL --retry 3 https://raw.githubusercontent.com/MHSanaei/3x-ui/main/install.sh -o /tmp/3x-ui-install.sh \
        || die "Не удалось скачать install.sh 3x-ui"
    XUI_NONINTERACTIVE=1 \
    XUI_USERNAME="$XUI_USERNAME" XUI_PASSWORD="$XUI_PASSWORD" \
    XUI_PANEL_PORT="$XUI_PANEL_PORT" XUI_WEB_BASE_PATH="$XUI_WEB_BASE_PATH" \
    XUI_SSL_MODE="$XUI_SSL_MODE" XUI_SERVER_IP="$PUBLIC_IP" \
        bash /tmp/3x-ui-install.sh </dev/null || die "Установка 3x-ui завершилась с ошибкой"
    rm -f /tmp/3x-ui-install.sh
else
    log "3x-ui уже установлен, пропускаю установку."
fi

log "Применяю настройки панели ..."
$XUI_DIR/x-ui setting -username "$XUI_USERNAME" -password "$XUI_PASSWORD" \
    -port "$XUI_PANEL_PORT" -webBasePath "$XUI_WEB_BASE_PATH" >/dev/null
systemctl restart x-ui

umask 077
cat > $CONF_DIR/xui.env <<EOF
XUI_USERNAME='$XUI_USERNAME'
XUI_PASSWORD='$XUI_PASSWORD'
XUI_PANEL_PORT='$XUI_PANEL_PORT'
XUI_WEB_BASE_PATH='$XUI_WEB_BASE_PATH'
EOF
umask 022

scheme=http
cert=$($XUI_DIR/x-ui setting -getCert true 2>/dev/null | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]') || cert=""
[[ -n $cert ]] && scheme=https
PANEL_LOCAL="$scheme://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH"

for _ in $(seq 1 30); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "$PANEL_LOCAL/" || true)
    [[ $code != 000 ]] && break
    sleep 1
done

XUI_TOKEN=$($XUI_DIR/x-ui setting -getApiToken 2>/dev/null | grep -Eo 'apiToken: .+' | awk '{print $2}') || XUI_TOKEN=""
COOKIE_JAR=$(mktemp)
CSRF=""
trap 'rm -f "$COOKIE_JAR"' EXIT

if [[ -z $XUI_TOKEN ]]; then
    # Фолбэк для версий без API-токена: сессионная кука + CSRF
    curl -sk -c "$COOKIE_JAR" -H 'Content-Type: application/json' \
        --data "$(jq -nc --arg u "$XUI_USERNAME" --arg p "$XUI_PASSWORD" '{username:$u,password:$p}')" \
        "$PANEL_LOCAL/login" | jq -e '.success' >/dev/null || die "Не удалось войти в панель 3x-ui"
    CSRF=$(curl -sk -b "$COOKIE_JAR" "$PANEL_LOCAL/csrf-token" 2>/dev/null \
        | jq -r '.obj | if type=="object" then (.token // .csrfToken // "") else (. // "") end' 2>/dev/null) || CSRF=""
fi

api() {
    local method=$1 path=$2 data=${3:-}
    local args=(-sSk --max-time 20 -X "$method" -H 'Accept: application/json')
    if [[ -n $XUI_TOKEN ]]; then
        args+=(-H "Authorization: Bearer $XUI_TOKEN")
    else
        args+=(-b "$COOKIE_JAR")
        [[ -n $CSRF ]] && args+=(-H "X-CSRF-Token: $CSRF")
    fi
    [[ -n $data ]] && args+=(-H 'Content-Type: application/json' --data "$data")
    curl "${args[@]}" "$PANEL_LOCAL$path"
}

JQ_DEFS='def j: if type=="string" then (fromjson? // {}) else (. // {}) end;'

list=$(api GET /panel/api/inbounds/list)
jq -e '.success' >/dev/null <<<"$list" || die "API 3x-ui не отвечает: $list"
existing=$(jq -c --arg r "$INBOUND_REMARK" '[.obj[]? | select(.remark==$r)][0] // empty' <<<"$list")

if [[ -n $existing ]]; then
    log "Inbound '$INBOUND_REMARK' уже существует, использую его."
    CLIENT_ID=$(jq -r "$JQ_DEFS"' .settings | j | .clients[0].id' <<<"$existing")
    INBOUND_PORT=$(jq -r '.port' <<<"$existing")
    PBK=$(jq -r "$JQ_DEFS"' .streamSettings | j | .realitySettings.settings.publicKey' <<<"$existing")
    REALITY_SNI=$(jq -r "$JQ_DEFS"' .streamSettings | j | .realitySettings.serverNames[0]' <<<"$existing")
    SID=$(jq -r "$JQ_DEFS"' .streamSettings | j | .realitySettings.shortIds[0]' <<<"$existing")
else
    log "Создаю inbound VLESS + Reality на порту $INBOUND_PORT ..."
    if ss -Hltn "sport = :$INBOUND_PORT" | grep -q .; then
        die "Порт $INBOUND_PORT уже занят. Задайте другой через INBOUND_PORT=..."
    fi
    keys=$(api GET /panel/api/server/getNewX25519Cert)
    PRIV=$(jq -r '.obj.privateKey // empty' <<<"$keys")
    PBK=$(jq -r '.obj.publicKey // empty' <<<"$keys")
    if [[ -z $PRIV || -z $PBK ]]; then
        xray_bin=$(ls $XUI_DIR/bin/xray-linux-* 2>/dev/null | head -n1)
        out=$("$xray_bin" x25519)
        PRIV=$(grep -i 'private' <<<"$out" | awk -F': ' '{print $2}' | tr -d '[:space:]')
        PBK=$(grep -iE 'public|password' <<<"$out" | head -n1 | awk -F': ' '{print $2}' | tr -d '[:space:]')
    fi
    [[ -n $PRIV && -n $PBK ]] || die "Не удалось сгенерировать ключи Reality"
    CLIENT_ID=$(cat /proc/sys/kernel/random/uuid)
    SID=$(openssl rand -hex 8)
    SUB_ID=$(rand 16 | tr 'A-Z' 'a-z')

    payload=$(jq -nc \
        --arg remark "$INBOUND_REMARK" --argjson port "$INBOUND_PORT" \
        --arg id "$CLIENT_ID" --arg email "client-$(rand 6 | tr 'A-Z' 'a-z')" --arg sub "$SUB_ID" \
        --arg sni "$REALITY_SNI" --arg priv "$PRIV" --arg pbk "$PBK" --arg sid "$SID" '
    {
      enable: true, remark: $remark, listen: "", port: $port, protocol: "vless",
      expiryTime: 0, total: 0, up: 0, down: 0,
      settings: {
        clients: [{ id: $id, flow: "xtls-rprx-vision", email: $email, limitIp: 0,
                    totalGB: 0, expiryTime: 0, enable: true, tgId: "", subId: $sub,
                    comment: "", reset: 0 }],
        decryption: "none", fallbacks: []
      },
      streamSettings: {
        network: "tcp", security: "reality", externalProxy: [],
        realitySettings: {
          show: false, xver: 0, target: ($sni + ":443"), serverNames: [$sni],
          privateKey: $priv, minClientVer: "", maxClientVer: "", maxTimediff: 0,
          shortIds: [$sid],
          settings: { publicKey: $pbk, fingerprint: "chrome", serverName: "", spiderX: "/" }
        },
        tcpSettings: { acceptProxyProtocol: false, header: { type: "none" } }
      },
      sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false, routeOnly: false }
    }')
    resp=$(api POST /panel/api/inbounds/add "$payload")
    jq -e '.success' >/dev/null <<<"$resp" || die "Не удалось создать inbound: $resp"
fi

VLESS_LINK="vless://${CLIENT_ID}@${PUBLIC_IP}:${INBOUND_PORT}?type=tcp&security=reality&pbk=${PBK}&fp=chrome&sni=${REALITY_SNI}&sid=${SID}&spx=%2F&flow=xtls-rprx-vision#${INBOUND_REMARK}"

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    log "ufw активен — открываю порты $INBOUND_PORT и $XUI_PANEL_PORT"
    ufw allow "$INBOUND_PORT/tcp" >/dev/null
    ufw allow "$XUI_PANEL_PORT/tcp" >/dev/null
fi

# ---------------------------------------------------------------------------
# Итог
# ---------------------------------------------------------------------------

PANEL_URL="$scheme://$PUBLIC_IP:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH/"

summary() {
    echo "================ Панель 3x-ui ================"
    echo "  URL      : $PANEL_URL"
    echo "  Логин    : $XUI_USERNAME"
    echo "  Пароль   : $XUI_PASSWORD"
    [[ -n $XUI_TOKEN ]] && echo "  APIтокен : $XUI_TOKEN"
    [[ $scheme == http ]] && echo "  (панель по HTTP; безопаснее через SSH: ssh -L 8080:127.0.0.1:$XUI_PANEL_PORT root@$PUBLIC_IP → http://localhost:8080/$XUI_WEB_BASE_PATH/)"
    echo
    echo "================ Клиент VLESS + Reality ================"
    echo "  Адрес    : $PUBLIC_IP:$INBOUND_PORT"
    echo "  UUID     : $CLIENT_ID"
    echo "  SNI      : $REALITY_SNI"
    echo "  PubKey   : $PBK"
    echo "  ShortId  : $SID"
    echo
    echo "  $VLESS_LINK"
    echo
    echo "================ Туннель ================"
    echo "  Выходной сервер : $VPN_SERVER_IP"
    echo "  Внешний IP      : ${EXIT_IP:-?}"
    echo "  Статус          : l2tp-exit status"
    echo "  Логи            : journalctl -u l2tp-exit -f"
    echo "  Отключить       : l2tp-exit down && systemctl disable l2tp-exit"
}

umask 077
summary > $ACCESS_FILE
umask 022

echo
echo -e "${blue}"
summary
echo -e "${plain}"
qrencode -t ansiutf8 "$VLESS_LINK" 2>/dev/null || true
echo
log "Данные сохранены в $ACCESS_FILE"
