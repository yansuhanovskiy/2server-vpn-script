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
# 4. (L2TP_SERVER=1) Поднимает L2TP/IPsec сервер для обычных клиентов (Windows,
#    macOS, iOS, роутеры), их трафик тоже уходит через сервер №2.
#
# Обязательные переменные (их печатает exit-server.sh):
#   VPN_SERVER_IP  VPN_IPSEC_PSK  VPN_USER  VPN_PASSWORD
#
# Необязательные:
#   INBOUND_PORT=443                 порт VLESS Reality
#   REALITY_SNI=<авто>               домен для маскировки Reality. По умолчанию ищется
#                                    автоматически: сайт из той же сети, что и сервер
#                                    (TLS 1.3 + h2, валидный сертификат). ТСПУ режет
#                                    Reality с «чужим» SNI на российском IP хостинга.
#   TRANSPORT=xhttp                  xhttp (стабильнее через ТСПУ) | tcp (Vision)
#   INBOUND_REMARK=vless-reality     имя inbound в панели
#   XUI_USERNAME / XUI_PASSWORD      логин/пароль панели (иначе случайные)
#   XUI_PANEL_PORT                   порт панели (иначе случайный)
#   XUI_WEB_BASE_PATH                секретный путь панели (иначе случайный)
#   XUI_SSL_MODE=none                none | ip | domain (см. install.sh 3x-ui)
#   KILL_SWITCH=1                    при падении туннеля не выпускать трафик напрямую
#   DISABLE_IPV6=1                   выключить IPv6 (туннель только IPv4, иначе утечки)
#   SET_DNS=1                        свой резолвер на сервере (запросы идут через туннель)
#   DNS_SERVERS="1.1.1.1 8.8.8.8"    DNS для сервера (при SET_DNS=1) и для L2TP-клиентов
#   WEBUI=1                          веб-интерфейс управления туннелем (вход: root + пароль)
#   XUI_VERSION=v3.8.5               версия 3x-ui (проверенная; latest — на свой риск)
#   L2TP_SERVER=1                    L2TP/IPsec сервер на этом узле (0 — не ставить)
#   L2TP_PSK / L2TP_USER / L2TP_PASSWORD  данные для L2TP-клиентов (иначе случайные)
#   SUB_DOMAIN=vpn.example.com       домен (A-запись на этот сервер): сертификат Let's
#                                    Encrypt, HTTPS для подписки и панели. Нужен свободный
#                                    порт 80. Без него подписка только по HTTP, а Happ
#                                    такие не принимает.
#
# Повторный запуск безопасен: конфиги перезаписываются, существующий inbound
# и учётные данные панели переиспользуются.

set -euo pipefail

CONN=l2tp-exit
CONF_DIR=/etc/l2tp-exit
HELPER=/usr/local/sbin/l2tp-exit
XUI_DIR=/usr/local/x-ui
ACCESS_FILE=/root/vpn-access.txt
SCRIPT_VERSION=14-multi

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; blue='\033[0;34m'; plain='\033[0m'
log()  { echo -e "${green}==>${plain} $*"; }
warn() { echo -e "${yellow}WARN:${plain} $*" >&2; }
die()  { echo -e "${red}ERROR:${plain} $*" >&2; exit 1; }

rand() {
    local s
    s=$(openssl rand -base64 96 | tr -dc 'A-Za-z0-9')
    printf '%s' "${s:0:$1}"
}

# Годится ли домен как цель Reality: TLS 1.3 + h2 + валидный сертификат
sni_check() {
    timeout 6 openssl s_client -connect "$1:443" -servername "$1" -tls1_3 -alpn h2 \
        -verify_return_error -CApath /etc/ssl/certs </dev/null 2>/dev/null | grep -q 'ALPN protocol: h2'
}

# Проверяет один адрес: берёт имена из сертификата и оставляет то, которое
# резолвится ровно в этот адрес и проходит sni_check
sni_probe() {
    local ip=$1 out n
    out=$(timeout 5 openssl s_client -connect "$ip:443" -tls1_3 -alpn h2 </dev/null 2>/dev/null) || return 0
    grep -q 'ALPN protocol: h2' <<<"$out" || return 0
    for n in $(openssl x509 -noout -text 2>/dev/null <<<"$out" | grep -o 'DNS:[^,]*' | cut -d: -f2 | grep -v '^\*' | head -n 8); do
        getent ahostsv4 "$n" | awk '{print $1}' | grep -qx "$ip" || continue
        sni_check "$n" || continue
        echo "$n"
        return 0
    done
    return 0
}
export -f sni_check sni_probe

# SNI для Reality: сайт из той же сети, что и сервер. Для ТСПУ такой SNI на этом
# IP выглядит естественно, а «чужой» (www.microsoft.com и т.п.) — нет.
pick_sni() {
    local asn cand base
    asn=$(curl -fsS --max-time 10 "https://stat.ripe.net/data/network-info/data.json?resource=$PUBLIC_IP" 2>/dev/null \
        | jq -r '.data.asns[0] // empty' 2>/dev/null) || asn=""
    # Проверенные вручную варианты для известных хостингов
    case $asn in
        29182) cand=firstvds.ru ;;   # FirstVDS
        *) cand="" ;;
    esac
    if [[ -n $cand ]] && sni_check "$cand"; then
        echo "$cand"
        return 0
    fi
    base=${PUBLIC_IP%.*}
    log "Ищу домен для Reality среди соседних адресов $base.0/24 (AS${asn:-?}), до минуты ..." >&2
    cand=$(seq 1 254 | grep -vx "${PUBLIC_IP##*.}" \
        | xargs -P 32 -I{} bash -c "sni_probe $base.{}" 2>/dev/null \
        | sort -u \
        | grep -viE 'vpn|proxy|xray|v2ray|vless|trojan|panel|test|dev|mail|autodiscover|ydns|fvds|xn--' \
        | awk '{print length($0), $0}' | sort -n | awk 'NR==1{print $2}') || true
    [[ -n $cand ]] && echo "$cand"
    return 0
}

# ---------------------------------------------------------------------------
# Проверки и параметры
# ---------------------------------------------------------------------------

log "entry-server.sh, версия $SCRIPT_VERSION"
[[ $EUID -eq 0 ]] || die "Запустите от root."
[[ -f /etc/debian_version ]] || die "Поддерживаются только Debian/Ubuntu."

# Значение из сохранённых настроек (их меняет и веб-интерфейс): при повторном
# запуске не нужно заново передавать данные сервера №2 и выбранные режимы
saved() {
    [[ -f $CONF_DIR/$CONN.env ]] || return 0
    ( . "$CONF_DIR/$CONN.env" 2>/dev/null; eval "printf '%s' \"\${$1:-}\"" )
}

for v in VPN_SERVER_IP VPN_IPSEC_PSK VPN_USER VPN_PASSWORD; do
    [[ -n ${!v:-} ]] || printf -v "$v" '%s' "$(saved "$v")"
    [[ -n ${!v:-} ]] || die "Не задана переменная $v. Возьмите команду из вывода exit-server.sh."
done
[[ $VPN_SERVER_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VPN_SERVER_IP должен быть IPv4-адресом."
for v in "$VPN_IPSEC_PSK" "$VPN_USER" "$VPN_PASSWORD"; do
    [[ $v =~ [\\\"\'[:space:]] ]] && die "Логин/пароль/PSK не должны содержать пробелы и символы \\ \" '"
done

INBOUND_PORT=${INBOUND_PORT:-443}
REALITY_SNI=${REALITY_SNI:-}
TRANSPORT=${TRANSPORT:-xhttp}
[[ $TRANSPORT == xhttp || $TRANSPORT == tcp ]] || die "TRANSPORT должен быть xhttp или tcp"
INBOUND_REMARK=${INBOUND_REMARK:-vless-reality}
XUI_SSL_MODE=${XUI_SSL_MODE:-none}
KILL_SWITCH=${KILL_SWITCH:-$(saved KILL_SWITCH)}; KILL_SWITCH=${KILL_SWITCH:-1}
DISABLE_IPV6=${DISABLE_IPV6:-1}
SET_DNS=${SET_DNS:-$(saved SET_DNS)}; SET_DNS=${SET_DNS:-1}
DNS_SERVERS=${DNS_SERVERS:-$(saved DNS_SERVERS)}; DNS_SERVERS=${DNS_SERVERS:-1.1.1.1 8.8.8.8}
for d in $DNS_SERVERS; do
    [[ $d =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "DNS_SERVERS: '$d' — не IPv4-адрес"
done
WEBUI=${WEBUI:-1}
MAIN_TITLE=${MAIN_TITLE:-$(saved MAIN_TITLE)}; MAIN_TITLE=${MAIN_TITLE:-Основной}
[[ $MAIN_TITLE =~ [\'\"\\] ]] && die "MAIN_TITLE: без кавычек"
XUI_VERSION=${XUI_VERSION:-v3.8.5}
L2TP_SERVER=${L2TP_SERVER:-1}
L2TP_NET=192.168.50
SUB_DOMAIN=${SUB_DOMAIN:-}
SUB_DOMAIN=${SUB_DOMAIN,,}
[[ -z $SUB_DOMAIN || $SUB_DOMAIN =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$ ]] || die "SUB_DOMAIN: некорректный домен"

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
# Данные L2TP-сервера: env > сохранённые > случайные
saved_l2psk=$(saved L2TP_PSK); saved_l2user=$(saved L2TP_USER); saved_l2pass=$(saved L2TP_PASSWORD)
if [[ -z $saved_l2psk && -f $CONF_DIR/l2tp-server.env ]]; then   # формат до версии 12
    # shellcheck disable=SC1091
    { saved_l2psk=$(. "$CONF_DIR/l2tp-server.env"; echo "$L2TP_PSK")
      saved_l2user=$(. "$CONF_DIR/l2tp-server.env"; echo "$L2TP_USER")
      saved_l2pass=$(. "$CONF_DIR/l2tp-server.env"; echo "$L2TP_PASSWORD"); }
fi
L2TP_PSK=${L2TP_PSK:-${saved_l2psk:-$(rand 24)}}
L2TP_USER=${L2TP_USER:-${saved_l2user:-vpn}}
L2TP_PASSWORD=${L2TP_PASSWORD:-${saved_l2pass:-$(rand 16)}}
for v in "$L2TP_PSK" "$L2TP_USER" "$L2TP_PASSWORD"; do
    [[ $v =~ ^[A-Za-z0-9._@-]+$ ]] || die "L2TP логин/пароль/PSK: только латиница, цифры и . _ @ -"
done
[[ $L2TP_PSK == "$VPN_IPSEC_PSK" ]] && die "L2TP_PSK должен отличаться от PSK сервера №2"

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
# Адрес для ссылок доп. выходов: домен, если есть, иначе IP
ENTRY_HOST=${SUB_DOMAIN:-$(saved ENTRY_HOST)}; ENTRY_HOST=${ENTRY_HOST:-$PUBLIC_IP}

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
    xl2tpd ppp iproute2 iptables curl jq openssl qrencode ca-certificates python3 >/dev/null

SWAN_UNIT=""
for u in strongswan.service strongswan-swanctl.service; do
    if systemctl cat "$u" >/dev/null 2>&1; then SWAN_UNIT=$u; break; fi
done
[[ -n $SWAN_UNIT ]] || die "Не найден systemd-юнит strongSwan (charon-systemd)."

# ---------------------------------------------------------------------------
# IPsec (swanctl) + L2TP (xl2tpd) + PPP
# ---------------------------------------------------------------------------

log "Настраиваю IPsec/L2TP клиент до $VPN_SERVER_IP ..."
[[ -f /etc/xl2tpd/xl2tpd.conf && ! -f /etc/xl2tpd/xl2tpd.conf.orig ]] \
    && cp /etc/xl2tpd/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf.orig

# Хуки pppd: маршрут туннеля в его таблицу (основной и доп. выходы)
cat > /etc/ppp/ip-up.d/$CONN <<'EOF'
#!/bin/sh
case "$PPP_IPPARAM" in
    l2tp-exit*) exec /usr/local/sbin/l2tp-exit ppp-up "$PPP_IPPARAM" "$PPP_IFACE" ;;
esac
EOF
cat > /etc/ppp/ip-down.d/$CONN <<'EOF'
#!/bin/sh
case "$PPP_IPPARAM" in
    l2tp-exit*) exec /usr/local/sbin/l2tp-exit ppp-down "$PPP_IPPARAM" "$PPP_IFACE" ;;
esac
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
CONF_DIR=/etc/l2tp-exit
EXITS_DIR=$CONF_DIR/exits.d
CTL=/var/run/xl2tpd/l2tp-control
IFACE_FILE=/run/l2tp-exit.iface
SIG_FILE=/run/l2tp-exit.routes
MARK_BASE=8192
EXIT_PORTS="2053 2083 2087 2443 3443 4443 5443 6443 7443"
. $CONF_DIR/l2tp-exit.env

log() { echo "l2tp-exit: $*"; }

# ---------------------------------------------------------------- выходы
#
# «main» — основной туннель из l2tp-exit.env: через него идут трафик самого
# сервера, L2TP-клиенты и основной VLESS. Дополнительные выходы лежат в
# exits.d/<имя>.env; у каждого свой туннель, таблица маршрутизации 202+N
# и метка пакетов 8192+N, которой Xray помечает трафик «своего» подключения.

exit_names() {
    local f
    for f in "$EXITS_DIR"/*.env; do
        [ -f "$f" ] && basename "$f" .env
    done
}

uplinks() { echo main; exit_names; }

# load_uplink <имя>: U_CONN U_IP U_PSK U_USER U_PASS U_TABLE U_MARK U_IFACE_FILE U_TITLE U_PORT
load_uplink() {
    if [ "$1" = main ]; then
        U_CONN=$CONN; U_IP=$VPN_SERVER_IP; U_PSK=$VPN_IPSEC_PSK; U_USER=$VPN_USER; U_PASS=$VPN_PASSWORD
        U_TABLE=$T_TUN; U_MARK=""; U_IFACE_FILE=$IFACE_FILE; U_TITLE=${MAIN_TITLE:-Основной}; U_PORT=""
        return 0
    fi
    [ -f "$EXITS_DIR/$1.env" ] || return 1
    local NAME TITLE SERVER_IP PSK USER PASSWORD INDEX PORT
    . "$EXITS_DIR/$1.env"
    U_CONN=$CONN-$1; U_IP=$SERVER_IP; U_PSK=$PSK; U_USER=$USER; U_PASS=$PASSWORD
    U_TABLE=$((T_TUN + INDEX)); U_MARK=$((MARK_BASE + INDEX))
    U_IFACE_FILE=/run/$CONN-$1.iface; U_TITLE=$TITLE; U_PORT=$PORT
}

# Имя выхода по имени IPsec/L2TP-соединения (для ip-up/ip-down)
uplink_by_conn() {
    case "$1" in
        "$CONN") echo main ;;
        "$CONN"-*) echo "${1#"$CONN"-}" ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------- маршрутизация
#
# Прямой трафик смотрит в НЕИЗМЕНЁННУЮ таблицу main (исходная маршрутизация
# сервера), поэтому SSH идёт ровно тем путём, что и до установки.
#   pref 999   TCP с исходящим портом sshd  -> main
#   pref 1000  to <IP любого сервера №2>    -> main (IKE/ESP/L2TP идут напрямую)
#   pref 1001  from <IP на WAN>             -> main (ответы клиентам, SSH, панель)
#   pref 1002  main без default             -> подсети провайдера, peer ppp и т.д.
#   pref 1003  fwmark 8192+N                -> 202+N (подключение доп. выхода)
#   pref 1004  всё остальное                -> 202 (основной туннель)
# В таблице каждого туннеля при KILL_SWITCH=1 стоит unreachable (трафик выхода
# никуда не уходит), при KILL_SWITCH=0 у доп. выходов — прямой маршрут через
# провайдера, а основной просто проваливается в main.

PREFS="999 1000 1001 1002 1003 1004"

flush_rules() {
    local p
    for p in $PREFS; do
        while ip -4 rule del pref $p 2>/dev/null; do :; done
    done
}

ssh_ports() {
    { sshd -T 2>/dev/null | awk '$1=="port"{print $2}'; echo 22; } | sort -u
}

wan_line() { ip -4 route show default table main | head -n1; }

wan_dev() {
    wan_line | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

wan_gw() {
    wan_line | awk '{for(i=1;i<NF;i++) if($i=="via"){print $(i+1); exit}}'
}

wan_ip() {
    ip -4 -o addr show dev "$(wan_dev)" scope global | awk '{split($4,a,"/"); print a[1]; exit}'
}

# Маршрут туннеля в его таблицу (из ip-up и после перестройки правил)
tunnel_route() {
    local u=$1 ifc
    load_uplink "$u" || return 1
    [ -f "$U_IFACE_FILE" ] || return 0
    ifc=$(cat "$U_IFACE_FILE")
    ip link show "$ifc" >/dev/null 2>&1 && ip route replace default dev "$ifc" metric 50 table "$U_TABLE"
}

apply_routes() {
    local dev gw ips sig ip port u ups=""
    [ -n "$(wan_line)" ] || { log "нет default-маршрута в main, правила не применяю"; flush_rules; return 1; }
    dev=$(wan_dev); gw=$(wan_gw)
    ips=$(ip -4 -o addr show dev "$dev" scope global | awk '{split($4,a,"/"); print a[1]}' | tr '\n' ' ')
    for u in $(uplinks); do load_uplink "$u" && ups="$ups $u:$U_IP:$U_TABLE:$U_MARK"; done
    sig="$dev|$gw|$ips|$(ssh_ports | tr '\n' ' ')|$ups|$KILL_SWITCH"
    if [ "$sig" = "$(cat $SIG_FILE 2>/dev/null)" ] && ip -4 rule show pref 1004 | grep -q .; then
        return 0
    fi
    log "применяю маршруты ($sig)"
    flush_rules
    for port in $(ssh_ports); do
        ip -4 rule add pref 999 ipproto tcp sport "$port" lookup main 2>/dev/null
    done
    for u in $(uplinks); do
        load_uplink "$u" || continue
        ip -4 rule add pref 1000 to "$U_IP" lookup main
    done
    for ip in $ips; do
        ip -4 rule add pref 1001 from "$ip" lookup main
    done
    ip -4 rule add pref 1002 lookup main suppress_prefixlength 0
    for u in $(exit_names); do
        load_uplink "$u" || continue
        ip -4 rule add pref 1003 fwmark "$U_MARK" lookup "$U_TABLE"
    done
    ip -4 rule add pref 1004 lookup $T_TUN

    for u in $(uplinks); do
        load_uplink "$u" || continue
        ip route del unreachable default metric 4000 table "$U_TABLE" 2>/dev/null
        ip route del default metric 4000 table "$U_TABLE" 2>/dev/null
        if [ "$KILL_SWITCH" = "1" ]; then
            ip route replace unreachable default metric 4000 table "$U_TABLE"
        elif [ "$u" != main ]; then
            # «Работать напрямую»: упавший доп. выход идёт через провайдера,
            # а не через соседний туннель
            if [ -n "$gw" ]; then
                ip route replace default via "$gw" dev "$dev" onlink metric 4000 table "$U_TABLE"
            else
                ip route replace default dev "$dev" metric 4000 table "$U_TABLE"
            fi
        fi
        tunnel_route "$u"
    done
    ip route flush cache
    echo "$sig" > $SIG_FILE
}

remove_routes() {
    local u
    flush_rules
    ip route flush table 201 2>/dev/null   # от старых версий скрипта
    for u in $(uplinks); do
        load_uplink "$u" && ip route flush table "$U_TABLE" 2>/dev/null
    done
    rm -f $SIG_FILE
    ip route flush cache
}

# ---------------------------------------------------------------- L2TP-клиенты: NAT и файрвол

fw() {
    local t=$1 c=$2; shift 2
    iptables -w -t "$t" -C "$c" "$@" -m comment --comment l2tp-exit 2>/dev/null \
        || iptables -w -t "$t" -I "$c" 1 "$@" -m comment --comment l2tp-exit
}

fw_rules() {
    local net="$L2TP_NET.0/24"
    # NAT только в ppp-интерфейсы: если туннель лёг, трафик клиентов
    # не уйдёт напрямую через провайдера сервера №1
    fw nat POSTROUTING -s "$net" ! -d "$net" -o ppp+ -j MASQUERADE
    fw filter FORWARD -s "$net" -j ACCEPT
    fw filter FORWARD -d "$net" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    fw mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    # Режим «работать напрямую»: пока туннель лежит, клиенты выходят через провайдера
    local wdev; wdev=$(wan_dev)
    if [ "$KILL_SWITCH" = "1" ]; then
        while iptables -w -t nat -D POSTROUTING -s "$net" ! -d "$net" -o "$wdev" -j MASQUERADE \
            -m comment --comment l2tp-exit 2>/dev/null; do :; done
    elif [ -n "$wdev" ]; then
        fw nat POSTROUTING -s "$net" ! -d "$net" -o "$wdev" -j MASQUERADE
    fi
    # L2TP принимаем только внутри IPsec
    fw filter INPUT -p udp --dport 1701 -m policy --dir in --pol none -j DROP
}

remove_fw() {
    local t line
    for t in nat filter mangle; do
        iptables -w -t "$t" -S 2>/dev/null | grep -- '--comment l2tp-exit' | sed 's/^-A /-D /' \
            | while read -r line; do eval iptables -w -t "$t" "$line"; done
    done
}

apply_fw() {
    if [ "${L2TP_SERVER:-0}" = "1" ]; then fw_rules 2>/dev/null || log "не все правила iptables применились"; else remove_fw; fi
}

# ---------------------------------------------------------------- конфиги

# DNS: resolv.conf сервера (SET_DNS=1) и ms-dns для L2TP-клиентов
apply_dns() {
    local s
    if [ -f /etc/ppp/options.l2tp-server ]; then
        sed -i '/^ms-dns /d' /etc/ppp/options.l2tp-server
        for s in $DNS_SERVERS; do echo "ms-dns $s" >> /etc/ppp/options.l2tp-server; done
    fi
    if [ "${SET_DNS:-0}" = "1" ]; then
        # Статический resolv.conf: DNS провайдера может не отвечать на запросы с IP
        # выходного сервера и/или подменять ответы. Запросы идут через туннель.
        [ -e /etc/resolv.conf.l2tp-exit.bak ] || cp -P /etc/resolv.conf /etc/resolv.conf.l2tp-exit.bak 2>/dev/null
        rm -f /etc/resolv.conf
        { for s in $DNS_SERVERS; do echo "nameserver $s"; done; echo "options timeout:2 attempts:2"; } > /etc/resolv.conf
    elif [ -e /etc/resolv.conf.l2tp-exit.bak ] || [ -L /etc/resolv.conf.l2tp-exit.bak ]; then
        rm -f /etc/resolv.conf
        mv /etc/resolv.conf.l2tp-exit.bak /etc/resolv.conf
    fi
}

# Генерирует конфиги strongSwan, xl2tpd и ppp для всех выходов
apply_config() {
    local wip u conns="" secrets="" lacs=""
    wip=$(wan_ip)
    [ -n "$wip" ] || { log "не удалось определить внешний адрес сервера"; return 1; }
    umask 077

    # У каждого выхода свой PSK, поэтому у каждого явно указан id сервера №2
    # (hwdsl2 представляется leftid=<публичный IP>): без него remote id = %any,
    # все PSK подходят одинаково и charon может взять чужой.
    # Алгоритмы подобраны под Libreswan-конфиг hwdsl2 (ike=aes256-sha2;modp2048,...)
    for u in $(uplinks); do
        load_uplink "$u" || continue
        conns="$conns
    $U_CONN {
        version = 1
        remote_addrs = $U_IP
        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048
        dpd_delay = 30s
        local {
            auth = psk
        }
        remote {
            auth = psk
            id = $U_IP
        }
        children {
            $U_CONN {
                mode = transport
                local_ts = dynamic[udp/1701]
                remote_ts = dynamic[udp/1701]
                esp_proposals = aes256-sha256,aes128-sha1,aes256-sha1
                dpd_action = restart
                start_action = none
            }
        }
    }"
        secrets="$secrets
    ike-$U_CONN {
        id-uplink = $U_IP
        secret = \"$U_PSK\"
    }"
        lacs="$lacs
[lac $U_CONN]
lns = $U_IP
ppp debug = no
pppoptfile = /etc/ppp/options.$U_CONN
length bit = yes
"
        # Маршруты pppd не трогает (nodefaultroute) — ими управляет этот хелпер.
        # ipparam позволяет хукам ip-up/ip-down узнать «свой» интерфейс.
        cat > /etc/ppp/options.$U_CONN <<EOF
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
ipparam $U_CONN
name "$U_USER"
password "$U_PASS"
EOF
    done
    # Удалённые выходы
    for f in /etc/ppp/options.$CONN-*; do
        [ -f "$f" ] || continue
        [ -f "$EXITS_DIR/${f#/etc/ppp/options.$CONN-}.env" ] || rm -f "$f"
    done

    # L2TP-сервер для своих клиентов живёт в том же charon и том же xl2tpd:
    # второй IPsec-демон (например, Libreswan от hwdsl2) конфликтовал бы за UDP 500/4500.
    if [ "${L2TP_SERVER:-0}" = "1" ]; then
        conns="$conns
    l2tp-server {
        version = 1
        remote_addrs = %any
        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,aes256-sha256-modp1024,aes256-sha1-modp1024,aes128-sha1-modp1024
        dpd_delay = 30s
        rekey_time = 0s
        local {
            auth = psk
        }
        remote {
            auth = psk
        }
        children {
            l2tp-server {
                mode = transport
                local_ts = dynamic[udp/1701]
                remote_ts = dynamic[udp]
                esp_proposals = aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1
                dpd_action = clear
                rekey_time = 0s
            }
        }
    }"
        secrets="$secrets
    ike-l2tp-server {
        secret = \"$L2TP_PSK\"
    }"
    fi

    printf 'connections {%s\n}\n\nsecrets {%s\n}\n' "$conns" "$secrets" > /etc/swanctl/conf.d/$CONN.conf

    # listen-addr обязателен: на 0.0.0.0 адрес отправителя ответов выбирается по
    # маршрутизации, и ответы L2TP-клиентам уходили бы в туннель с чужим адресом
    {
        printf '[global]\nlisten-addr = %s\n\n' "$wip"
        if [ "${L2TP_SERVER:-0}" = "1" ]; then
            cat <<EOF
[lns default]
ip range = $L2TP_NET.10-$L2TP_NET.250
local ip = $L2TP_NET.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.l2tp-server
length bit = yes
EOF
        fi
        printf '%s' "$lacs"
    } > /etc/xl2tpd/xl2tpd.conf

    touch /etc/ppp/chap-secrets
    sed -i '/# l2tp-exit-server$/d' /etc/ppp/chap-secrets
    if [ "${L2TP_SERVER:-0}" = "1" ]; then
        cat > /etc/ppp/options.l2tp-server <<EOF
+mschap-v2
require-mschap-v2
ipcp-accept-local
ipcp-accept-remote
noccp
auth
mtu 1280
mru 1280
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
connect-delay 5000
EOF
        # Наша строка в chap-secrets помечена комментарием, чужие не трогаем
        printf '"%s" l2tpd "%s" * # l2tp-exit-server\n' "$L2TP_USER" "$L2TP_PASSWORD" >> /etc/ppp/chap-secrets
    fi
    chmod 600 /etc/ppp/chap-secrets /etc/swanctl/conf.d/$CONN.conf
    umask 022
    apply_dns
}

# ---------------------------------------------------------------- туннели

ctl() {
    [ -p $CTL ] || return 1
    timeout 5 sh -c "echo '$1' > $CTL"
}

is_up() {
    local ifc
    load_uplink "$1" || return 1
    [ -f "$U_IFACE_FILE" ] || return 1
    ifc=$(cat "$U_IFACE_FILE")
    ip -4 addr show dev "$ifc" 2>/dev/null | grep -q 'inet '
}

connect() {
    local u=$1 i
    load_uplink "$u" || return 1
    if ! swanctl --list-sas --ike "$U_CONN" 2>/dev/null | grep -q INSTALLED; then
        swanctl --terminate --ike "$U_CONN" >/dev/null 2>&1
        swanctl --initiate --child "$U_CONN" --timeout 30 >/dev/null 2>&1 \
            || { log "[$u] IPsec не поднялся"; return 1; }
        log "[$u] IPsec SA установлена"
    fi
    ctl "d $U_CONN"
    sleep 1
    ctl "c $U_CONN" || { log "[$u] xl2tpd недоступен"; return 1; }
    for i in $(seq 1 30); do
        is_up "$u" && { log "[$u] PPP поднят: $(cat "$U_IFACE_FILE")"; return 0; }
        sleep 1
    done
    log "[$u] PPP не поднялся"
    return 1
}

# Подключение каждого выхода — в отдельном фоновом процессе: мёртвый выход
# не должен задерживать переподключение остальных
watch() {
    local u pidf fails
    swanctl --load-all --noprompt >/dev/null 2>&1
    rm -f /run/l2tp-exit-connect.*.pid
    while :; do
        apply_routes
        apply_fw
        for u in $(uplinks); do
            is_up "$u" && { rm -f "/run/l2tp-exit-fails.$u"; continue; }
            pidf=/run/l2tp-exit-connect.$u.pid
            if [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then continue; fi
            log "[$u] туннель не активен, подключаюсь"
            (
                if connect "$u"; then
                    rm -f "/run/l2tp-exit-fails.$u"
                else
                    fails=$(( $(cat "/run/l2tp-exit-fails.$u" 2>/dev/null || echo 0) + 1 ))
                    echo $fails > "/run/l2tp-exit-fails.$u"
                    # Перезапуск служб рвёт все туннели — только если долго лежит основной
                    if [ "$u" = main ] && [ $fails -ge 3 ]; then
                        log "перезапускаю $SWAN_UNIT и xl2tpd"
                        systemctl restart "$SWAN_UNIT" xl2tpd
                        sleep 3
                        swanctl --load-all --noprompt >/dev/null 2>&1
                        rm -f "/run/l2tp-exit-fails.$u"
                    fi
                fi
            ) &
            echo $! > "$pidf"
        done
        sleep 15
    done
}

# Внешний IP через выход: соединение с меткой выхода, как у трафика Xray
exit_ip() {
    load_uplink "$1" || return 1
    python3 - "${U_MARK:-0}" <<'PY' 2>/dev/null
import socket, sys
mark = int(sys.argv[1])
s = socket.socket()
if mark:
    s.setsockopt(socket.SOL_SOCKET, 36, mark)  # SO_MARK
s.settimeout(6)
s.connect((socket.gethostbyname('ipv4.icanhazip.com'), 80))
s.sendall(b'GET / HTTP/1.0\r\nHost: ipv4.icanhazip.com\r\n\r\n')
data = b''
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
print(data.split(b'\r\n\r\n', 1)[-1].decode().strip())
PY
}

apply_all() {
    apply_config || return 1
    swanctl --load-all --noprompt >/dev/null 2>&1
    reconnect
}

reconnect() {
    local u
    for u in $(uplinks); do
        load_uplink "$u" || continue
        ctl "d $U_CONN"
        swanctl --terminate --ike "$U_CONN" >/dev/null 2>&1
    done
    # Соединения удалённых выходов
    swanctl --list-sas 2>/dev/null | awk -F: '/^l2tp-exit-[^:]*: #/{print $1}' | sort -u | while read -r c; do
        [ -f "$EXITS_DIR/${c#"$CONN"-}.env" ] || swanctl --terminate --ike "$c" >/dev/null 2>&1
    done
    systemctl restart xl2tpd
    rm -f $SIG_FILE
    systemctl restart l2tp-exit
}

# ---------------------------------------------------------------- доп. выходы: 3x-ui

xui_api() {
    local method=$1 path=$2 data=${3:-} ctype=${4:-application/json}
    local args=(-sSk --max-time 20 -X "$method" -H "Authorization: Bearer $XUI_TOKEN" -H 'Accept: application/json')
    [ -n "$data" ] && args+=(-H "Content-Type: $ctype" --data "$data")
    curl "${args[@]}" "$XUI_BASE$path"
}

xui_init() {
    local port path scheme=http
    [ -f $CONF_DIR/xui.env ] || { log "нет $CONF_DIR/xui.env — 3x-ui не настроен"; return 1; }
    port=$(. $CONF_DIR/xui.env; echo "$XUI_PANEL_PORT")
    path=$(. $CONF_DIR/xui.env; echo "$XUI_WEB_BASE_PATH")
    /usr/local/x-ui/x-ui setting -getCert true 2>/dev/null | grep 'cert:' | awk -F': ' '{print $2}' \
        | grep -q '[^[:space:]]' && scheme=https
    XUI_BASE="$scheme://127.0.0.1:$port/$path"
    XUI_TOKEN=$(/usr/local/x-ui/x-ui setting -getApiToken 2>/dev/null | grep -Eo 'apiToken: .+' | awk '{print $2}')
    [ -n "$XUI_TOKEN" ] || { log "не удалось получить API-токен 3x-ui"; return 1; }
}

JQ_J='def j: if type=="string" then (fromjson? // {}) else (. // {}) end;'

# Для каждого выхода — копия основного inbound на своём порту (inbound
# «exit-<имя>», тот же subId клиента: одна подписка на все выходы), плюс в
# шаблоне Xray исходящий канал с меткой выхода и правило «inbound → канал».
xray_sync() {
    local list main u remark have payload resp tmpl new exits="[]" tag
    xui_init || return 1
    list=$(xui_api GET /panel/api/inbounds/list)
    echo "$list" | jq -e '.success' >/dev/null 2>&1 || { log "API 3x-ui не отвечает"; return 1; }
    main=$(echo "$list" | jq -c --arg r "${MAIN_INBOUND_REMARK:-vless-reality}" '[.obj[]? | select(.remark==$r)][0] // empty')
    [ -n "$main" ] || { log "нет основного inbound ${MAIN_INBOUND_REMARK:-vless-reality}"; return 1; }

    for u in $(exit_names); do
        load_uplink "$u" || continue
        remark="exit-$u"
        have=$(echo "$list" | jq -r --arg r "$remark" '[.obj[]? | select(.remark==$r)][0].port // empty')
        if [ -n "$have" ] && [ "$have" != "$U_PORT" ]; then
            xui_api POST "/panel/api/inbounds/del/$(echo "$list" | jq -r --arg r "$remark" '[.obj[]? | select(.remark==$r)][0].id')" >/dev/null
            have=""
        fi
        if [ -z "$have" ]; then
            payload=$(echo "$main" | jq -c --arg r "$remark" --argjson port "$U_PORT" \
                --arg id "$(cat /proc/sys/kernel/random/uuid)" --arg email "$remark-$(openssl rand -hex 3)" \
                --arg path "/$(openssl rand -hex 6)" "$JQ_J"'
                {enable: true, remark: $r, listen: "", port: $port, protocol: .protocol,
                 expiryTime: 0, total: 0, up: 0, down: 0,
                 settings: (.settings | j | .clients = [(.clients[0] // {}) + {id: $id, email: $email}]
                            | .clients[0] |= del(.created_at, .updated_at)),
                 streamSettings: (.streamSettings | j
                            | if .network == "xhttp" then .xhttpSettings.path = $path else . end),
                 sniffing: (.sniffing | j)}')
            resp=$(xui_api POST /panel/api/inbounds/add "$payload")
            echo "$resp" | jq -e '.success' >/dev/null 2>&1 || { log "[$u] не удалось создать inbound: $resp"; return 1; }
            log "[$u] создан inbound $remark на порту $U_PORT"
        fi
    done
    # inbound'ы удалённых выходов
    for id in $(echo "$list" | jq -r '.obj[]? | select(.remark|startswith("exit-")) | "\(.id) \(.remark)"' \
        | while read -r id r; do [ -f "$EXITS_DIR/${r#exit-}.env" ] || echo "$id"; done); do
        xui_api POST "/panel/api/inbounds/del/$id" >/dev/null
    done

    list=$(xui_api GET /panel/api/inbounds/list)
    for u in $(exit_names); do
        load_uplink "$u" || continue
        tag=$(echo "$list" | jq -r --arg r "exit-$u" '[.obj[]? | select(.remark==$r)][0].tag // empty')
        [ -n "$tag" ] || { log "[$u] не найден тег inbound"; return 1; }
        exits=$(echo "$exits" | jq -c --arg n "$u" --arg t "$tag" --argjson m "$U_MARK" '. + [{name: $n, tag: $t, mark: $m}]')
    done

    tmpl=$(xui_api POST /panel/api/xray/ | jq -r '.obj.xraySetting // empty')
    [ -n "$tmpl" ] || { log "не удалось прочитать шаблон Xray"; return 1; }
    # Наши каналы добавляются в конец (первый outbound — канал по умолчанию),
    # правила — тоже в конец, после блокировок 3x-ui (private IP, bittorrent)
    new=$(echo "$tmpl" | jq -c --argjson ex "$exits" '
        .outbounds = ([.outbounds[]? | select((.tag // "") | startswith("exit-") | not)]
                      + [$ex[] | {tag: ("exit-" + .name), protocol: "freedom",
                                  settings: {domainStrategy: "AsIs"},
                                  streamSettings: {sockopt: {mark: .mark}}}])
        | .routing.rules = ([.routing.rules[]? | select((.ruleTag // "") | startswith("l2tp-exit-") | not)]
                      + [$ex[] | {type: "field", ruleTag: ("l2tp-exit-" + .name),
                                  inboundTag: [.tag], outboundTag: ("exit-" + .name)}])')
    if [ "$(echo "$tmpl" | jq -S -c .)" != "$(echo "$new" | jq -S -c .)" ]; then
        resp=$(curl -sSk --max-time 20 -H "Authorization: Bearer $XUI_TOKEN" \
            --data-urlencode "xraySetting=$new" "$XUI_BASE/panel/api/xray/update")
        echo "$resp" | jq -e '.success' >/dev/null 2>&1 || { log "не удалось сохранить шаблон Xray: $resp"; return 1; }
        xui_api POST /panel/api/server/restartXrayService >/dev/null
        log "маршруты Xray для выходов обновлены"
    fi
}

# Ссылки vless:// доп. выходов (по образцу основного inbound)
links() {
    local list u host
    xui_init || return 1
    host=${ENTRY_HOST:-$(wan_ip)}
    list=$(xui_api GET /panel/api/inbounds/list)
    for u in $(exit_names); do
        load_uplink "$u" || continue
        echo "$list" | jq -r --arg r "exit-$u" --arg host "$host" --arg title "$U_TITLE" "$JQ_J"'
            [.obj[]? | select(.remark==$r)][0] // empty
            | (.settings | j) as $s | (.streamSettings | j) as $st | $st.realitySettings as $rs
            | "vless://\($s.clients[0].id)@\($host):\(.port)?type=\($st.network)&security=reality"
              + "&pbk=\($rs.settings.publicKey)&fp=\($rs.settings.fingerprint // "chrome")"
              + "&sni=\($rs.serverNames[0])&sid=\($rs.shortIds[0])&spx=%2F"
              + (if $st.network == "xhttp" then "&path=\($st.xhttpSettings.path | @uri)&mode=auto"
                 else "&flow=\($s.clients[0].flow // "")" end)
              + "&encryption=none#\($title | @uri)"'
    done
}

# ---------------------------------------------------------------- управление выходами

valid() { printf '%s' "$1" | grep -Eq '^[^[:space:]"\\'"'"']{1,128}$'; }

# exit-add <имя> <название> <IP> <PSK> <логин> <пароль> [порт]
exit_add() {
    local name=$1 title=$2 ip=$3 psk=$4 user=$5 pass=$6 port=${7:-} idx used p u
    printf '%s' "$name" | grep -Eq '^[a-z][a-z0-9]{0,11}$' || { log "имя: латиница/цифры, до 12 символов (например de, in)"; return 1; }
    [ "$name" != main ] || { log "имя main занято основным туннелем"; return 1; }
    printf '%s' "$ip" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || { log "IP указан неверно"; return 1; }
    for v in "$psk" "$user" "$pass"; do valid "$v" || { log "логин/пароль/PSK: без пробелов и кавычек"; return 1; }; done
    printf '%s' "$title" | grep -q "['\"\\\\]" && { log "в названии не должно быть кавычек"; return 1; }
    [ -n "$title" ] || title=$name
    for u in $(uplinks); do
        load_uplink "$u" || continue
        [ "$U_IP" = "$ip" ] && [ "$u" != "$name" ] && { log "сервер $ip уже подключён как «${u}»"; return 1; }
        [ "$U_PSK" = "$psk" ] && [ "$u" != "$name" ] && { log "PSK совпадает с выходом «${u}» — нужны разные"; return 1; }
    done
    [ "$psk" = "${L2TP_PSK:-}" ] && { log "PSK совпадает с PSK L2TP-клиентов"; return 1; }

    # Повторное добавление того же имени = изменение: индекс и порт сохраняются,
    # иначе у клиентов перестала бы работать ссылка
    idx=""; used=" "
    for u in $(exit_names); do
        if [ "$u" = "$name" ]; then
            idx=$(. "$EXITS_DIR/$u.env"; echo "$INDEX")
            [ -n "$port" ] || port=$(. "$EXITS_DIR/$u.env"; echo "$PORT")
            continue
        fi
        used="$used$(. "$EXITS_DIR/$u.env"; echo "$INDEX $PORT") "
    done
    if [ -z "$idx" ]; then
        for i in 1 2 3 4 5 6 7 8 9; do case "$used" in *" $i "*) ;; *) idx=$i; break ;; esac; done
        [ -n "$idx" ] || { log "не больше 9 дополнительных выходов"; return 1; }
    fi
    if [ -z "$port" ]; then
        for p in $EXIT_PORTS; do
            case "$used" in *" $p "*) continue ;; esac
            ss -Hltn "sport = :$p" | grep -q . && continue
            port=$p; break
        done
    fi
    printf '%s' "$port" | grep -Eq '^[0-9]{2,5}$' || { log "не нашёл свободный порт, укажите его явно"; return 1; }

    mkdir -p "$EXITS_DIR"; chmod 700 "$EXITS_DIR"
    umask 077
    cat > "$EXITS_DIR/$name.env" <<EOF
NAME='$name'
TITLE='$title'
SERVER_IP='$ip'
PSK='$psk'
USER='$user'
PASSWORD='$pass'
INDEX='$idx'
PORT='$port'
EOF
    umask 022
    command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active' && ufw allow "$port/tcp" >/dev/null
    log "выход «${name}» ($title, $ip) сохранён, порт подключения $port"
    apply_all || return 1
    xray_sync
}

exit_del() {
    [ -f "$EXITS_DIR/$1.env" ] || { log "нет выхода «$1»"; return 1; }
    load_uplink "$1"
    rm -f "$EXITS_DIR/$1.env" "/etc/ppp/options.$U_CONN" "$U_IFACE_FILE"
    ip route flush table "$U_TABLE" 2>/dev/null
    apply_all
    xray_sync
    log "выход «$1» удалён"
}

# ---------------------------------------------------------------- статус

status() {
    local u ip
    for u in $(uplinks); do
        load_uplink "$u" || continue
        echo "=== $u ($U_TITLE) → $U_IP${U_PORT:+, подключение на порту $U_PORT}"
        if swanctl --list-sas --ike "$U_CONN" 2>/dev/null | grep -q INSTALLED; then echo "  IPsec : установлен"; else echo "  IPsec : нет"; fi
        if is_up "$u"; then
            ip=$(exit_ip "$u")
            echo "  PPP   : $(cat "$U_IFACE_FILE"), внешний IP ${ip:-?}"
        else
            echo "  PPP   : не поднят"
        fi
    done
    echo "=== правила"; ip -4 rule show | grep -E '^(999|100[0-4]):'
    if [ "${L2TP_SERVER:-0}" = "1" ]; then
        echo "=== L2TP-клиенты"; swanctl --list-sas --ike l2tp-server 2>/dev/null | grep -E '^l2tp-server' || echo "нет"
    fi
}

# Статус для веб-интерфейса
status_json() {
    local u first=1 up ipsec ip
    printf '['
    for u in $(uplinks); do
        load_uplink "$u" || continue
        up=false; ipsec=false; ip=""
        swanctl --list-sas --ike "$U_CONN" 2>/dev/null | grep -q INSTALLED && ipsec=true
        if is_up "$u"; then up=true; ip=$(exit_ip "$u"); fi
        [ $first = 1 ] || printf ','
        first=0
        jq -nc --arg n "$u" --arg t "$U_TITLE" --arg s "$U_IP" --arg p "$U_PORT" --argjson up $up \
            --argjson ipsec $ipsec --arg ip "$ip" \
            '{name: $n, title: $t, server: $s, port: $p, tunnel: $up, ipsec: $ipsec, exit_ip: $ip}'
    done
    printf ']\n'
}

case "${1:-}" in
    routes) apply_routes; apply_fw ;;
    apply-config) apply_config ;;
    apply) apply_all ;;
    apply-dns) apply_dns ;;
    reconnect) reconnect ;;
    watch)  watch ;;
    status) status ;;
    status-json) status_json ;;
    ppp-up)
        # из /etc/ppp/ip-up.d: ppp-up <ipparam> <iface>
        u=$(uplink_by_conn "$2") || exit 0
        load_uplink "$u" || exit 0
        echo "$3" > "$U_IFACE_FILE"
        ip route replace default dev "$3" metric 50 table "$U_TABLE"
        ip route flush cache
        ;;
    ppp-down)
        u=$(uplink_by_conn "$2") || exit 0
        load_uplink "$u" || exit 0
        rm -f "$U_IFACE_FILE"
        ip route del default dev "$3" metric 50 table "$U_TABLE" 2>/dev/null
        ;;
    exits) for u in $(exit_names); do load_uplink "$u"; echo "$u  $U_TITLE  $U_IP  порт $U_PORT"; done ;;
    exit-add) shift; exit_add "$@" ;;
    exit-del) exit_del "${2:-}" ;;
    xray-sync) xray_sync ;;
    links) links ;;
    down)
        systemctl stop l2tp-exit 2>/dev/null
        for u in $(uplinks); do load_uplink "$u" && { ctl "d $U_CONN"; swanctl --terminate --ike "$U_CONN" >/dev/null 2>&1; }; done
        remove_routes
        remove_fw
        log "туннели остановлены, маршрутизация возвращена к исходной"
        ;;
    *) echo "usage: $0 {status|down|reconnect|apply|exits|exit-add|exit-del|xray-sync|links|routes|watch}"; exit 1 ;;
esac
HELPER_EOF
chmod 755 $HELPER

# Все настройки — в одном файле; конфиги strongSwan/xl2tpd/ppp/DNS генерирует
# хелпер. Этот же файл правит веб-интерфейс, поэтому они не разъедутся.
umask 077
cat > $CONF_DIR/$CONN.env <<EOF
VPN_SERVER_IP='$VPN_SERVER_IP'
VPN_IPSEC_PSK='$VPN_IPSEC_PSK'
VPN_USER='$VPN_USER'
VPN_PASSWORD='$VPN_PASSWORD'
KILL_SWITCH='$KILL_SWITCH'
SET_DNS='$SET_DNS'
DNS_SERVERS='$DNS_SERVERS'
SWAN_UNIT='$SWAN_UNIT'
L2TP_SERVER='$L2TP_SERVER'
L2TP_NET='$L2TP_NET'
L2TP_PSK='$L2TP_PSK'
L2TP_USER='$L2TP_USER'
L2TP_PASSWORD='$L2TP_PASSWORD'
MAIN_INBOUND_REMARK='$INBOUND_REMARK'
MAIN_TITLE='$MAIN_TITLE'
ENTRY_HOST='$ENTRY_HOST'
EOF
umask 022
rm -f $CONF_DIR/l2tp-server.env
$HELPER apply-config || die "Не удалось сгенерировать конфиги туннеля"

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
# sysctl: IPv6, rp_filter, форвардинг для L2TP-клиентов
# ---------------------------------------------------------------------------

{
    echo "net.ipv4.conf.all.rp_filter = 2"
    echo "net.ipv4.conf.default.rp_filter = 2"
    if [[ $L2TP_SERVER == 1 ]]; then
        echo "net.ipv4.ip_forward = 1"
        echo "net.ipv4.conf.all.accept_redirects = 0"
        echo "net.ipv4.conf.all.send_redirects = 0"
    fi
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


# ---------------------------------------------------------------------------
# 3x-ui
# ---------------------------------------------------------------------------

if [[ ! -x $XUI_DIR/x-ui ]]; then
    # Версия закреплена: API 3x-ui меняется между релизами (так уже ломалось поле tgId)
    if [[ $XUI_VERSION == latest ]]; then xui_ref=main; xui_arg=""; else xui_ref=$XUI_VERSION; xui_arg=$XUI_VERSION; fi
    log "Устанавливаю 3x-ui ${xui_arg:-latest} ..."
    curl -fsSL --retry 3 "https://raw.githubusercontent.com/MHSanaei/3x-ui/$xui_ref/install.sh" -o /tmp/3x-ui-install.sh \
        || die "Не удалось скачать install.sh 3x-ui ($xui_ref)"
    XUI_NONINTERACTIVE=1 \
    XUI_USERNAME="$XUI_USERNAME" XUI_PASSWORD="$XUI_PASSWORD" \
    XUI_PANEL_PORT="$XUI_PANEL_PORT" XUI_WEB_BASE_PATH="$XUI_WEB_BASE_PATH" \
    XUI_SSL_MODE="$XUI_SSL_MODE" XUI_SERVER_IP="$PUBLIC_IP" \
        bash /tmp/3x-ui-install.sh $xui_arg </dev/null || die "Установка 3x-ui завершилась с ошибкой"
    rm -f /tmp/3x-ui-install.sh
else
    log "3x-ui уже установлен, пропускаю установку."
fi

SUB_CERT=""; SUB_KEY=""
if [[ -n $SUB_DOMAIN ]]; then
    log "Получаю сертификат Let's Encrypt для $SUB_DOMAIN ..."
    dom_ips=$(getent ahostsv4 "$SUB_DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ')
    grep -qw "$PUBLIC_IP" <<<"$dom_ips" \
        || die "$SUB_DOMAIN указывает на [${dom_ips:-ничего}], а не на $PUBLIC_IP. Настройте A-запись (без проксирования Cloudflare) и перезапустите."
    if ss -Hltn "sport = :80" | grep -q .; then
        die "Порт 80 занят — он нужен Let's Encrypt для проверки домена. Освободите его и перезапустите."
    fi
    apt-get install -y -qq socat cron >/dev/null
    ACME=/root/.acme.sh/acme.sh
    if [[ ! -x $ACME ]]; then
        curl -fsSL --retry 3 https://get.acme.sh | sh >/dev/null || die "Не удалось установить acme.sh"
    fi
    $ACME --set-default-ca --server letsencrypt >/dev/null
    rc=0
    $ACME --issue -d "$SUB_DOMAIN" --standalone --httpport 80 --keylength ec-256 >/tmp/acme.log 2>&1 || rc=$?
    # 2 = сертификат уже есть и ещё не пора обновлять
    if [[ $rc != 0 && $rc != 2 ]]; then
        tail -20 /tmp/acme.log >&2
        die "Let's Encrypt не выдал сертификат. Проверьте, что порт 80 открыт у провайдера."
    fi
    SUB_CERT=/root/cert/$SUB_DOMAIN/fullchain.pem
    SUB_KEY=/root/cert/$SUB_DOMAIN/privkey.pem
    mkdir -p "/root/cert/$SUB_DOMAIN"
    # reloadcmd не должен падать: acme.sh считает его ошибку ошибкой установки,
    # а веб-интерфейса при первом запуске ещё нет
    $ACME --install-cert -d "$SUB_DOMAIN" --ecc \
        --fullchain-file "$SUB_CERT" --key-file "$SUB_KEY" \
        --reloadcmd "systemctl restart x-ui; systemctl try-restart l2tp-exit-web || true" >>/tmp/acme.log 2>&1 \
        || { tail -20 /tmp/acme.log >&2; die "Не удалось установить сертификат (лог выше и в /tmp/acme.log)"; }
    chmod 600 "$SUB_KEY"
    $XUI_DIR/x-ui cert -webCert "$SUB_CERT" -webCertKey "$SUB_KEY" >/dev/null \
        || warn "Не удалось включить HTTPS для панели"
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
    ex_net=$(jq -r "$JQ_DEFS"' .streamSettings | j | .network' <<<"$existing")
    ex_sni=$(jq -r "$JQ_DEFS"' .streamSettings | j | .realitySettings.serverNames[0]' <<<"$existing")
    # Без явного REALITY_SNI сохраняем SNI существующего inbound
    [[ -z $REALITY_SNI ]] && REALITY_SNI=$ex_sni
    if [[ $ex_net != "$TRANSPORT" || $ex_sni != "$REALITY_SNI" ]]; then
        log "Inbound '$INBOUND_REMARK' ($ex_net, SNI $ex_sni) пересоздаю как $TRANSPORT, SNI $REALITY_SNI — ссылка изменится."
        old_port=$(jq -r '.port' <<<"$existing")
        api POST "/panel/api/inbounds/del/$(jq -r '.id' <<<"$existing")" >/dev/null
        existing=""
        for _ in $(seq 1 20); do
            ss -Hltn "sport = :$old_port" | grep -q . || break
            sleep 1
        done
    fi
fi

if [[ -n $existing ]]; then
    log "Inbound '$INBOUND_REMARK' уже существует, использую его."
    CLIENT_ID=$(jq -r "$JQ_DEFS"' .settings | j | .clients[0].id' <<<"$existing")
    SUB_ID=$(jq -r "$JQ_DEFS"' .settings | j | .clients[0].subId // empty' <<<"$existing")
    INBOUND_PORT=$(jq -r '.port' <<<"$existing")
    PBK=$(jq -r "$JQ_DEFS"' .streamSettings | j | .realitySettings.settings.publicKey' <<<"$existing")
    SID=$(jq -r "$JQ_DEFS"' .streamSettings | j | .realitySettings.shortIds[0]' <<<"$existing")
    XHTTP_PATH=$(jq -r "$JQ_DEFS"' .streamSettings | j | .xhttpSettings.path // "/"' <<<"$existing")
else
    if [[ -z $REALITY_SNI ]]; then
        REALITY_SNI=$(pick_sni)
        [[ -n $REALITY_SNI ]] || die "Не нашёл подходящий домен для Reality в сети сервера.
  Подберите сайт, который хостится у того же провайдера (TLS 1.3 + h2), и перезапустите
  скрипт с REALITY_SNI=домен. Всё остальное уже настроено, повторный запуск быстрый."
        log "Домен для Reality: $REALITY_SNI"
    fi
    log "Создаю inbound VLESS + Reality ($TRANSPORT, SNI $REALITY_SNI) на порту $INBOUND_PORT ..."
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
    XHTTP_PATH="/$(openssl rand -hex 6)"
    FLOW=""
    [[ $TRANSPORT == tcp ]] && FLOW=xtls-rprx-vision

    payload=$(jq -nc \
        --arg remark "$INBOUND_REMARK" --argjson port "$INBOUND_PORT" --arg net "$TRANSPORT" \
        --arg id "$CLIENT_ID" --arg flow "$FLOW" --arg email "client-$(rand 6 | tr 'A-Z' 'a-z')" --arg sub "$SUB_ID" \
        --arg sni "$REALITY_SNI" --arg priv "$PRIV" --arg pbk "$PBK" --arg sid "$SID" --arg path "$XHTTP_PATH" '
    {
      enable: true, remark: $remark, listen: "", port: $port, protocol: "vless",
      expiryTime: 0, total: 0, up: 0, down: 0,
      settings: {
        clients: [{ id: $id, flow: $flow, email: $email, limitIp: 0,
                    totalGB: 0, expiryTime: 0, enable: true, subId: $sub,
                    comment: "", reset: 0 }],
        decryption: "none", fallbacks: []
      },
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
    jq -e '.success' >/dev/null <<<"$resp" || die "Не удалось создать inbound: $resp"

    # Битая настройка роняет весь Xray — проверяем, что порт реально слушается
    listening=0
    for _ in $(seq 1 20); do
        ss -Hltn "sport = :$INBOUND_PORT" | grep -q . && { listening=1; break; }
        sleep 1
    done
    if [[ $listening != 1 ]]; then
        journalctl -u x-ui -n 30 --no-pager | grep -m1 'Failed to start' >&2 || true
        die "Xray не запустился с новым inbound. Удалите '$INBOUND_REMARK' в панели и пришлите ошибку выше."
    fi
fi

if [[ $TRANSPORT == xhttp ]]; then
    VLESS_LINK="vless://${CLIENT_ID}@${PUBLIC_IP}:${INBOUND_PORT}?type=xhttp&security=reality&pbk=${PBK}&fp=chrome&sni=${REALITY_SNI}&sid=${SID}&spx=%2F&path=${XHTTP_PATH//\//%2F}&mode=auto&encryption=none#${INBOUND_REMARK}"
else
    VLESS_LINK="vless://${CLIENT_ID}@${PUBLIC_IP}:${INBOUND_PORT}?type=tcp&security=reality&pbk=${PBK}&fp=chrome&sni=${REALITY_SNI}&sid=${SID}&spx=%2F&flow=xtls-rprx-vision&encryption=none#${INBOUND_REMARK}"
fi

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    log "ufw активен — открываю порты $INBOUND_PORT и $XUI_PANEL_PORT"
    ufw allow "$INBOUND_PORT/tcp" >/dev/null
    ufw allow "$XUI_PANEL_PORT/tcp" >/dev/null
    if [[ $L2TP_SERVER == 1 ]]; then
        ufw allow 500/udp >/dev/null
        ufw allow 4500/udp >/dev/null
    fi
fi

# ---------------------------------------------------------------------------
# Итог
# ---------------------------------------------------------------------------

# Доп. выходы (exits.d): их inbound'ы и маршруты Xray — после основного inbound
EXIT_LINKS=""
if [[ -n $(ls $CONF_DIR/exits.d/*.env 2>/dev/null) ]]; then
    log "Синхронизирую дополнительные выходы ..."
    $HELPER xray-sync || warn "Не удалось настроить дополнительные выходы в 3x-ui (см. выше)"
    EXIT_LINKS=$($HELPER links 2>/dev/null) || EXIT_LINKS=""
fi

SUB_URL=""
if [[ -n $SUB_DOMAIN ]]; then
    log "Включаю подписку по HTTPS на $SUB_DOMAIN ..."
    settings=$(api POST /panel/api/setting/all)
    jq -e '.success' >/dev/null <<<"$settings" || die "Не удалось прочитать настройки панели: $settings"
    new_settings=$(jq -c --arg d "$SUB_DOMAIN" --arg c "$SUB_CERT" --arg k "$SUB_KEY" \
        '.obj | .subEnable = true | .subDomain = $d | .subCertFile = $c | .subKeyFile = $k' <<<"$settings")
    resp=$(api POST /panel/api/setting/update "$new_settings")
    jq -e '.success' >/dev/null <<<"$resp" || die "Не удалось сохранить настройки подписки: $resp"
    systemctl restart x-ui
    sub_port=$(jq -r '.subPort' <<<"$new_settings")
    sub_path=$(jq -r '.subPath // "/sub/"' <<<"$new_settings")
    sub_path="/${sub_path#/}"; sub_path="${sub_path%/}/"
    [[ -n ${SUB_ID:-} ]] && SUB_URL="https://$SUB_DOMAIN:$sub_port$sub_path$SUB_ID"
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
        ufw allow 80/tcp >/dev/null
        ufw allow "$sub_port/tcp" >/dev/null
    fi
    # Панель теперь тоже по HTTPS — показываем её по домену
    scheme=https
    PANEL_HOST=$SUB_DOMAIN
fi

PANEL_URL="$scheme://${PANEL_HOST:-$PUBLIC_IP}:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH/"

# ---------------------------------------------------------------------------
# Веб-интерфейс управления туннелем
# ---------------------------------------------------------------------------

WEBUI_URL=""
if [[ $WEBUI == 1 ]]; then
    log "Ставлю веб-интерфейс управления туннелем ..."
    apt-get install -y -qq python3 >/dev/null
    install -d -m 755 /usr/local/lib/l2tp-exit
    cat > /usr/local/lib/l2tp-exit/webui.py <<'WEBUI_EOF'
#!/usr/bin/env python3
# l2tp-exit web UI: настройки подключения к серверу №2, поведение при падении
# туннеля, DNS. Вход по логину root и его системному паролю (PAM).
# Ставится entry-server.sh; только стандартная библиотека Python.

import ctypes
import ctypes.util
import hmac
import html
import http.server
import ipaddress
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

ENV_FILE = '/etc/l2tp-exit/l2tp-exit.env'
HELPER = '/usr/local/sbin/l2tp-exit'
IFACE_FILE = '/run/l2tp-exit.iface'
EXITS_DIR = '/etc/l2tp-exit/exits.d'
PAM_SERVICE = 'l2tp-exit-web'
ALLOWED_USER = 'root'
SESSION_TTL = 12 * 3600
MAX_FAILS = 5
LOCK_SECONDS = 15 * 60

# --------------------------------------------------------------------- PAM

_libpam = ctypes.CDLL(ctypes.util.find_library('pam') or 'libpam.so.0')
_libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6')

PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2


class _PamMessage(ctypes.Structure):
    _fields_ = [('msg_style', ctypes.c_int), ('msg', ctypes.c_char_p)]


class _PamResponse(ctypes.Structure):
    _fields_ = [('resp', ctypes.c_void_p), ('resp_retcode', ctypes.c_int)]


_CONV = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int,
                         ctypes.POINTER(ctypes.POINTER(_PamMessage)),
                         ctypes.POINTER(ctypes.POINTER(_PamResponse)), ctypes.c_void_p)


class _PamConv(ctypes.Structure):
    _fields_ = [('conv', _CONV), ('appdata_ptr', ctypes.c_void_p)]


_libc.calloc.restype = ctypes.c_void_p
_libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
_libc.strdup.restype = ctypes.c_void_p
_libc.strdup.argtypes = [ctypes.c_char_p]
_libpam.pam_start.restype = ctypes.c_int
_libpam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.POINTER(_PamConv), ctypes.POINTER(ctypes.c_void_p)]
for _f in ('pam_authenticate', 'pam_acct_mgmt', 'pam_end'):
    getattr(_libpam, _f).restype = ctypes.c_int
    getattr(_libpam, _f).argtypes = [ctypes.c_void_p, ctypes.c_int]

_pam_lock = threading.Lock()


def pam_authenticate(user, password):
    secret = password.encode()

    @_CONV
    def conv(n, messages, response, _data):
        # Ответы выделяются через libc: PAM сам освобождает их free()
        arr = _libc.calloc(n, ctypes.sizeof(_PamResponse))
        if not arr:
            return 5  # PAM_BUF_ERR
        resp = ctypes.cast(arr, ctypes.POINTER(_PamResponse))
        for i in range(n):
            if messages[i].contents.msg_style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                resp[i].resp = _libc.strdup(secret)
        response[0] = resp
        return 0

    handle = ctypes.c_void_p()
    conversation = _PamConv(conv, None)
    with _pam_lock:
        rc = _libpam.pam_start(PAM_SERVICE.encode(), user.encode(),
                               ctypes.byref(conversation), ctypes.byref(handle))
        if rc != 0:
            return False
        rc = _libpam.pam_authenticate(handle, 0)
        if rc == 0:
            rc = _libpam.pam_acct_mgmt(handle, 0)
        _libpam.pam_end(handle, rc)
    return rc == 0

# --------------------------------------------------------------------- settings

SAFE_VALUE = re.compile(r"^[^'\"\\\s]{1,128}$")


def read_env():
    env = {}
    with open(ENV_FILE) as f:
        for line in f:
            m = re.match(r'^([A-Z0-9_]+)=(.*)$', line.strip())
            if not m:
                continue
            v = m.group(2)
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            env[m.group(1)] = v
    return env


def write_env(env):
    tmp = ENV_FILE + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        for k, v in env.items():
            if "'" in v or '\n' in v:
                raise ValueError(k)
            f.write(f"{k}='{v}'\n")
    os.replace(tmp, ENV_FILE)


def run(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, 'timeout'
    except OSError as e:
        return 127, str(e)


def status():
    rc, out = run([HELPER, 'status-json'], 60)
    try:
        tunnels = json.loads(out) if rc == 0 else []
    except ValueError:
        tunnels = []
    _, out = run(['swanctl', '--list-sas', '--ike', 'l2tp-server'], 10)
    return {'tunnels': tunnels, 'l2tp_clients': len(re.findall(r'^l2tp-server: #', out, re.M))}


def read_exits():
    exits = []
    try:
        names = sorted(f[:-4] for f in os.listdir(EXITS_DIR) if f.endswith('.env'))
    except OSError:
        return exits
    for name in names:
        d = {}
        try:
            with open(os.path.join(EXITS_DIR, name + '.env')) as f:
                for line in f:
                    m = re.match(r"^([A-Z_]+)='(.*)'$", line.strip())
                    if m:
                        d[m.group(1)] = m.group(2)
        except OSError:
            continue
        exits.append({'name': name, 'title': d.get('TITLE', name), 'ip': d.get('SERVER_IP', ''),
                      'port': d.get('PORT', '')})
    return exits

# --------------------------------------------------------------------- sessions

_sessions = {}   # token -> {'exp': ts, 'csrf': str}
_fails = {}      # ip -> [count, locked_until]
_state_lock = threading.Lock()


def new_session():
    token = secrets.token_urlsafe(32)
    with _state_lock:
        _sessions[token] = {'exp': time.time() + SESSION_TTL, 'csrf': secrets.token_urlsafe(24)}
    return token


def get_session(token):
    with _state_lock:
        s = _sessions.get(token or '')
        if s and s['exp'] > time.time():
            return s
        _sessions.pop(token or '', None)
    return None


def locked(ip):
    with _state_lock:
        f = _fails.get(ip)
        return bool(f and f[1] > time.time())


def register_fail(ip):
    with _state_lock:
        f = _fails.setdefault(ip, [0, 0])
        f[0] += 1
        if f[0] >= MAX_FAILS:
            f[0], f[1] = 0, time.time() + LOCK_SECONDS

# --------------------------------------------------------------------- pages

MESSAGES = {
    'uplink': ('ok', 'Настройки сервера №2 сохранены. Туннель переподключается, это займёт до минуты.'),
    'mode': ('ok', 'Режим сохранён.'),
    'dns': ('ok', 'DNS сохранены. L2TP-клиенты получат их при следующем подключении.'),
    'reconnect': ('ok', 'Туннель переподключается, это займёт до минуты.'),
    'bad_ip': ('err', 'IP сервера №2 указан неверно.'),
    'bad_value': ('err', "Логин, пароль и PSK не должны содержать пробелы и символы ' \" \\."),
    'bad_dns': ('err', 'DNS: укажите от 1 до 4 IPv4-адресов через пробел или запятую.'),
    'same_psk': ('err', 'PSK сервера №2 должен отличаться от PSK L2TP-клиентов этого сервера.'),
    'apply_failed': ('err', 'Не удалось применить настройки, подробности в journalctl -u l2tp-exit-web.'),
    'csrf': ('err', 'Сессия устарела, обновите страницу.'),
    'exit_added': ('ok', 'Выход сохранён. Туннели переподключаются, это займёт до минуты. Ссылки — в «Ссылках для подключения» или в подписке.'),
    'exit_deleted': ('ok', 'Выход удалён.'),
    'bad_exit': ('err', 'Имя выхода — латиница и цифры, до 12 символов, начинается с буквы (например de, in). В названии не должно быть кавычек.'),
}

CSS = '''
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#6b7280;--line:#e5e7eb;--accent:#2563eb;
--ok:#15803d;--okbg:#ecfdf3;--err:#b91c1c;--errbg:#fef2f2}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8ee;--muted:#9aa3b2;
--line:#2a2f3a;--accent:#60a5fa;--ok:#4ade80;--okbg:#0f2a1a;--err:#f87171;--errbg:#2a1212}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:760px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:0 0 12px}
.sub{color:var(--muted);margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin:0 0 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.k{color:var(--muted);font-size:13px}.v{font-weight:600}
label{display:block;margin:10px 0 4px;font-size:14px}
input[type=text],input[type=password]{width:100%;padding:9px 10px;border:1px solid var(--line);
border-radius:8px;background:var(--bg);color:var(--fg);font:inherit}
.opt{display:flex;gap:10px;align-items:flex-start;margin:10px 0}.opt input{margin-top:4px}
.hint{color:var(--muted);font-size:13px;margin:4px 0 0}
button{margin-top:14px;padding:9px 16px;border:0;border-radius:8px;background:var(--accent);
color:#fff;font:inherit;font-weight:600;cursor:pointer}
button.ghost{background:transparent;color:var(--accent);border:1px solid var(--line)}
.msg{padding:10px 14px;border-radius:8px;margin:0 0 16px}
.msg.ok{background:var(--okbg);color:var(--ok)}.msg.err{background:var(--errbg);color:var(--err)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;background:var(--muted)}
.up{background:var(--ok)}.down{background:var(--err)}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--muted);font-weight:500;font-size:13px}td form{margin:0}td button{margin:0;padding:4px 9px;font-size:13px}
td.t,td.ip{white-space:nowrap}td:last-child{width:1%}
.tbl{overflow-x:auto}.row2{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}
@media (max-width:560px){.row2{grid-template-columns:1fr}}
textarea{width:100%;min-height:90px;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:13px/1.4 ui-monospace,Menlo,monospace}
'''


def page(title, body):
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>{CSS}</style></head><body><main>{body}</main></body></html>'''


def login_page(error=''):
    err = f'<div class="msg err">{html.escape(error)}</div>' if error else ''
    return page('Вход — туннель', f'''
<h1>Управление туннелем</h1><p class="sub">Сервер №1. Войдите под root с системным паролем.</p>
{err}<form class="card" method="post" action="/login">
<label for="u">Пользователь</label><input type="text" id="u" name="user" value="root" autocomplete="username">
<label for="p">Пароль</label><input type="password" id="p" name="password" autocomplete="current-password" autofocus>
<button type="submit">Войти</button></form>''')


def main_page(sess, msg_code):
    env = read_env()
    exits = read_exits()
    e = lambda k, d='': html.escape(env.get(k, d), quote=True)
    csrf = f'<input type="hidden" name="csrf" value="{sess["csrf"]}">'
    msg = ''
    if msg_code in MESSAGES:
        kind, text = MESSAGES[msg_code]
        msg = f'<div class="msg {kind}">{html.escape(text)}</div>'
    flash = sess.pop('flash', None)
    if flash:
        msg += f'<div class="msg {flash[0]}">{html.escape(flash[1])}</div>'
    rows = ''.join(f'''<tr data-n="{html.escape(x["name"])}"><td><b>{html.escape(x["title"])}</b>
<div class="hint">{html.escape(x["name"])} · {html.escape(x["ip"])} · порт {html.escape(x["port"])}</div></td>
<td class="t">…</td><td class="ip">…</td><td><form method="post" action="/exit-del"
onsubmit="return confirm('Удалить выход {html.escape(x["title"])}? Подключение на порту {html.escape(x["port"])} перестанет работать.')">{csrf}
<input type="hidden" name="name" value="{html.escape(x["name"])}"><button class="ghost" type="submit" title="Удалить выход" aria-label="Удалить выход">✕</button></form></td></tr>'''
                   for x in exits)
    ks = env.get('KILL_SWITCH', '1') == '1'
    set_dns = env.get('SET_DNS', '1') == '1'
    return page('Туннель — сервер №1', f'''
<div class="top"><div><h1>Управление туннелем</h1>
<p class="sub">Сервер №1 · выходов: {1 + len(exits)}</p></div>
<form method="post" action="/logout">{csrf}<button class="ghost" type="submit">Выйти</button></form></div>
{msg}
<section class="card"><h2>Выходы</h2><div class="tbl"><table>
<thead><tr><th>Выход</th><th>Туннель</th><th>Внешний IP</th><th></th></tr></thead><tbody>
<tr data-n="main"><td><b>{e("MAIN_TITLE", "Основной")}</b><div class="hint">основной · {e("VPN_SERVER_IP")}</div></td>
<td class="t">…</td><td class="ip">…</td><td></td></tr>
{rows}</tbody></table></div>
<p class="hint">Через основной выход идут трафик самого сервера, L2TP-клиенты и основное подключение VLESS.
Каждый дополнительный выход — отдельное подключение VLESS на своём порту. L2TP-клиентов сейчас: <b id="st-l2tp">…</b></p>
<div style="display:flex;gap:10px;flex-wrap:wrap">
<form method="post" action="/reconnect">{csrf}<button class="ghost" type="submit">Переподключить туннели</button></form>
<form method="get" action="/links"><button class="ghost" type="submit">Ссылки для подключения</button></form></div>
</section>

<form class="card" method="post" action="/exit-add">{csrf}<h2>Добавить выход</h2>
<p class="hint">На новом выходном сервере сначала запустите <code>exit-server.sh</code> — он напечатает IP, PSK, логин и пароль.</p>
<div class="row2">
<div><label for="xn">Имя (латиница)</label><input type="text" id="xn" name="name" placeholder="in" required pattern="[a-z][a-z0-9]{{0,11}}"></div>
<div><label for="xt">Название</label><input type="text" id="xt" name="title" placeholder="Индия" required></div>
<div><label for="xi">IP сервера</label><input type="text" id="xi" name="ip" required></div>
<div><label for="xp">Порт VLESS (необязательно)</label><input type="text" id="xp" name="port" placeholder="авто: 2053, 2083, …"></div>
<div><label for="xk">IPsec PSK</label><input type="password" id="xk" name="psk" required autocomplete="off"></div>
<div><label for="xu">Логин L2TP</label><input type="text" id="xu" name="user" required></div>
<div><label for="xw">Пароль L2TP</label><input type="password" id="xw" name="password" required autocomplete="off"></div>
</div>
<p class="hint">Для каждого выхода в 3x-ui создаётся копия основного подключения на своём порту. Клиенты получают его
в той же подписке. Если порт закрыт файрволом провайдера, откройте его. При добавлении туннели и L2TP-клиенты
переподключаются (до минуты). Существующее имя — это изменение выхода, порт при этом сохраняется.</p>
<button type="submit">Добавить</button></form>

<form class="card" method="post" action="/uplink">{csrf}<h2>Основной выход (сервер №2)</h2>
<label for="ip">IP-адрес</label><input type="text" id="ip" name="ip" value="{e("VPN_SERVER_IP")}" required>
<label for="psk">IPsec PSK</label><input type="password" id="psk" name="psk" placeholder="не менять" autocomplete="off">
<label for="user">Логин L2TP</label><input type="text" id="user" name="user" value="{e("VPN_USER")}" required>
<label for="pw">Пароль L2TP</label><input type="password" id="pw" name="password" placeholder="не менять" autocomplete="off">
<p class="hint">Пустые поля PSK и пароля оставляют текущие значения. После сохранения туннель переподключится.
Если данные неверны, он не поднимется, но эта страница останется доступна, и их можно будет исправить.</p>
<button type="submit">Сохранить и переподключить</button></form>

<form class="card" method="post" action="/mode">{csrf}<h2>Если туннель упал</h2>
<div class="opt"><input type="radio" id="m1" name="mode" value="block" {"checked" if ks else ""}>
<label for="m1" style="margin:0"><b>Блокировать всё</b><br><span class="hint">Клиенты VLESS и L2TP остаются без
интернета, пока туннель не вернётся. Их трафик никогда не выйдет с IP этого сервера.</span></label></div>
<div class="opt"><input type="radio" id="m2" name="mode" value="direct" {"" if ks else "checked"}>
<label for="m2" style="margin:0"><b>Работать напрямую</b><br><span class="hint">Пока туннель лежит, трафик идёт
через провайдера этого сервера (с его IP). Когда туннель поднимется, всё вернётся в него.</span></label></div>
<button type="submit">Сохранить</button></form>

<form class="card" method="post" action="/dns">{csrf}<h2>DNS</h2>
<label for="dns">DNS-серверы</label><input type="text" id="dns" name="dns" value="{e("DNS_SERVERS")}">
<p class="hint">IPv4-адреса через пробел, например <code>1.1.1.1 8.8.8.8</code>.
Их получают L2TP-клиенты, а при включённой галочке ниже — и сам сервер (VLESS, Xray, обновления).
Запросы идут через туннель.</p>
<div class="opt"><input type="checkbox" id="sd" name="set_dns" value="1" {"checked" if set_dns else ""}>
<label for="sd" style="margin:0">Использовать эти DNS на самом сервере<br><span class="hint">Если выключить,
вернётся исходный resolv.conf (обычно DNS провайдера: он может не отвечать на запросы через туннель
или подменять ответы).</span></label></div>
<button type="submit">Сохранить</button></form>

<script>
async function refresh(){{
  try{{
    const r=await fetch('/api/status',{{credentials:'same-origin'}}); if(!r.ok) return;
    const s=await r.json(); const dot=u=>'<span class="dot '+(u?'up':'down')+'"></span>';
    for(const t of s.tunnels){{
      const row=document.querySelector('tr[data-n="'+CSS.escape(t.name)+'"]'); if(!row) continue;
      row.querySelector('.t').innerHTML=dot(t.tunnel)+(t.tunnel?'работает':(t.ipsec?'IPsec есть, PPP нет':'не работает'));
      row.querySelector('.ip').textContent=t.exit_ip||'—';
    }}
    document.getElementById('st-l2tp').textContent=s.l2tp_clients;
  }}catch(e){{}}
}}
refresh(); setInterval(refresh,15000);
</script>''')

def helper_error(out):
    # Последние сообщения хелпера («l2tp-exit: ...») — понятная причина ошибки
    lines = [l.split('l2tp-exit: ', 1)[-1] for l in out.splitlines() if 'l2tp-exit: ' in l]
    return 'Не получилось: ' + (lines[-1] if lines else 'подробности в journalctl -u l2tp-exit-web')


def links_page():
    rc, out = run([HELPER, 'links'], 30)
    items = [l for l in out.splitlines() if l.startswith('vless://')] if rc == 0 else []
    try:
        with open('/root/vpn-access.txt') as f:
            acc = f.read()
        main_link = re.search(r'vless://\S+', acc)
        sub = re.search(r'https://\S+/sub/\S+', acc)
    except OSError:
        main_link = sub = None
    blocks = ''
    if sub:
        blocks += f'''<section class="card"><h2>Подписка (все выходы сразу)</h2>
<textarea readonly onclick="this.select()">{html.escape(sub.group(0))}</textarea>
<p class="hint">Добавьте её в Happ один раз: новые выходы появятся сами после обновления подписки.</p></section>'''
    if main_link:
        blocks += f'''<section class="card"><h2>Основной выход</h2>
<textarea readonly onclick="this.select()">{html.escape(main_link.group(0))}</textarea></section>'''
    for l in items:
        title = urllib.parse.unquote(l.rsplit('#', 1)[-1])
        blocks += f'''<section class="card"><h2>{html.escape(title)}</h2>
<textarea readonly onclick="this.select()">{html.escape(l)}</textarea></section>'''
    if not blocks:
        blocks = '<p class="card">Ссылок пока нет.</p>'
    return page('Ссылки — туннель', f'''<div class="top"><div><h1>Ссылки для подключения</h1>
<p class="sub">Скопируйте ссылку в Happ или другой клиент VLESS.</p></div>
<form method="get" action="/"><button class="ghost" type="submit">Назад</button></form></div>{blocks}''')


# --------------------------------------------------------------------- handler


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'l2tp-exit'
    sys_version = ''

    def setup(self):
        # Рукопожатие TLS — в потоке обработчика и с таймаутом: медленный или
        # «немой» клиент не должен блокировать приём остальных подключений
        self.request.settimeout(15)
        self.request.do_handshake()
        super().setup()

    def log_message(self, fmt, *args):
        sys.stderr.write('%s %s\n' % (self.client_address[0], fmt % args))

    def _send(self, code, body, ctype='text/html; charset=utf-8', headers=()):
        data = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Strict-Transport-Security', 'max-age=31536000')
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, where, headers=()):
        self.send_response(303)
        self.send_header('Location', where)
        self.send_header('Content-Length', '0')
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()

    def _token(self):
        for part in self.headers.get('Cookie', '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'sid':
                return v
        return ''

    def _form(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > 16384:
            return {}
        raw = self.rfile.read(n).decode('utf-8', 'replace')
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        sess = get_session(self._token())
        if url.path == '/login':
            return self._send(200, login_page())
        if not sess:
            return self._redirect('/login')
        if url.path == '/api/status':
            return self._send(200, json.dumps(status()), 'application/json')
        if url.path == '/links':
            return self._send(200, links_page())
        if url.path == '/':
            q = urllib.parse.parse_qs(url.query)
            return self._send(200, main_page(sess, q.get('m', [''])[0]))
        self._send(404, page('404', '<p>Не найдено.</p>'))

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        form = self._form()
        ip = self.client_address[0]

        if path == '/login':
            if locked(ip):
                return self._send(429, login_page('Слишком много попыток. Подождите 15 минут.'))
            user = form.get('user', '').strip()
            if user == ALLOWED_USER and pam_authenticate(user, form.get('password', '')):
                token = new_session()
                cookie = f'sid={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL}'
                return self._redirect('/', [('Set-Cookie', cookie)])
            register_fail(ip)
            time.sleep(1)
            return self._send(401, login_page('Неверный логин или пароль.'))

        sess = get_session(self._token())
        if not sess:
            return self._redirect('/login')
        if not hmac.compare_digest(form.get('csrf', ''), sess['csrf']):
            return self._redirect('/?m=csrf')

        if path == '/logout':
            with _state_lock:
                _sessions.pop(self._token(), None)
            return self._redirect('/login', [('Set-Cookie', 'sid=; Path=/; Max-Age=0; Secure; HttpOnly')])
        if path == '/reconnect':
            run([HELPER, 'reconnect'])
            return self._redirect('/?m=reconnect')
        if path == '/uplink':
            return self._redirect('/?m=' + self.save_uplink(form))
        if path == '/mode':
            env = read_env()
            env['KILL_SWITCH'] = '0' if form.get('mode') == 'direct' else '1'
            write_env(env)
            # Хелпер читает настройки при старте: перезапуск применит маршруты и NAT,
            # сам туннель при этом не рвётся
            run(['systemctl', 'restart', 'l2tp-exit'])
            return self._redirect('/?m=mode')
        if path == '/dns':
            return self._redirect('/?m=' + self.save_dns(form))
        if path == '/exit-add':
            return self._redirect('/?m=' + self.exit_add(form, sess))
        if path == '/exit-del':
            name = form.get('name', '')
            if not re.match(r'^[a-z][a-z0-9]{0,11}$', name):
                return self._redirect('/?m=bad_exit')
            rc, out = run([HELPER, 'exit-del', name], 180)
            if rc != 0:
                sess['flash'] = ('err', helper_error(out))
                return self._redirect('/')
            return self._redirect('/?m=exit_deleted')
        self._send(404, page('404', '<p>Не найдено.</p>'))

    def save_uplink(self, form):
        env = read_env()
        new = dict(env)
        try:
            new['VPN_SERVER_IP'] = str(ipaddress.IPv4Address(form.get('ip', '').strip()))
        except ValueError:
            return 'bad_ip'
        new['VPN_USER'] = form.get('user', '').strip()
        for field, key in (('psk', 'VPN_IPSEC_PSK'), ('password', 'VPN_PASSWORD')):
            if form.get(field):
                new[key] = form[field]
        for key in ('VPN_USER', 'VPN_IPSEC_PSK', 'VPN_PASSWORD'):
            if not SAFE_VALUE.match(new.get(key, '')):
                return 'bad_value'
        if new.get('L2TP_SERVER') == '1' and new['VPN_IPSEC_PSK'] == new.get('L2TP_PSK'):
            return 'same_psk'
        write_env(new)
        rc, out = run([HELPER, 'apply'])
        if rc != 0:
            sys.stderr.write('apply failed: %s\n' % out)
            return 'apply_failed'
        return 'uplink'

    def exit_add(self, form, sess):
        name = form.get('name', '').strip()
        title = form.get('title', '').strip()
        port = form.get('port', '').strip()
        if not re.match(r'^[a-z][a-z0-9]{0,11}$', name) or name == 'main' or not title \
                or re.search(r"['\"\\\n]", title) or len(title) > 40:
            return 'bad_exit'
        try:
            ip = str(ipaddress.IPv4Address(form.get('ip', '').strip()))
        except ValueError:
            return 'bad_ip'
        vals = [form.get(k, '') for k in ('psk', 'user', 'password')]
        if not all(SAFE_VALUE.match(v) for v in vals):
            return 'bad_value'
        if port and not re.match(r'^[0-9]{2,5}$', port):
            return 'bad_exit'
        cmd = [HELPER, 'exit-add', name, title, ip] + vals + ([port] if port else [])
        rc, out = run(cmd, 240)
        if rc != 0:
            sess['flash'] = ('err', helper_error(out))
            return ''
        return 'exit_added'

    def save_dns(self, form):
        items = [x for x in re.split(r'[\s,;]+', form.get('dns', '')) if x]
        try:
            servers = [str(ipaddress.IPv4Address(x)) for x in items]
        except ValueError:
            return 'bad_dns'
        if not 1 <= len(servers) <= 4:
            return 'bad_dns'
        env = read_env()
        env['DNS_SERVERS'] = ' '.join(servers)
        env['SET_DNS'] = '1' if form.get('set_dns') == '1' else '0'
        write_env(env)
        rc, out = run([HELPER, 'apply-dns'])
        if rc != 0:
            sys.stderr.write('apply-dns failed: %s\n' % out)
            return 'apply_failed'
        return 'dns'


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Сканеры и клиенты без TLS сыпят ошибками рукопожатия — не засоряем журнал
        pass


def main():
    port = int(os.environ['WEBUI_PORT'])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(os.environ['WEBUI_CERT'], os.environ['WEBUI_KEY'])
    srv = Server(('', port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    sys.stderr.write('l2tp-exit web UI on https://*:%d\n' % port)
    srv.serve_forever()


if __name__ == '__main__':
    main()
WEBUI_EOF
    # Отдельный PAM-сервис: у стандартного login есть pam_securetty, который
    # не пускает root без терминала
    cat > /etc/pam.d/l2tp-exit-web <<'EOF'
@include common-auth
@include common-account
EOF

    saved_wport=""; saved_wcert=""; saved_wkey=""
    if [[ -f $CONF_DIR/webui.env ]]; then
        saved_wport=$(. "$CONF_DIR/webui.env"; echo "${WEBUI_PORT:-}")
        saved_wcert=$(. "$CONF_DIR/webui.env"; echo "${WEBUI_CERT:-}")
        saved_wkey=$(. "$CONF_DIR/webui.env"; echo "${WEBUI_KEY:-}")
    fi
    WEBUI_PORT=${WEBUI_PORT:-$saved_wport}
    while [[ -z $WEBUI_PORT || $WEBUI_PORT == "$XUI_PANEL_PORT" || $WEBUI_PORT == "$INBOUND_PORT" ]]; do
        WEBUI_PORT=$(shuf -i 20000-60000 -n 1)
    done

    # Сертификат: домена (SUB_DOMAIN), иначе прежний, иначе самоподписанный
    if [[ -n $SUB_CERT ]]; then
        WEBUI_CERT=$SUB_CERT; WEBUI_KEY=$SUB_KEY
    elif [[ -f $saved_wcert && -f $saved_wkey ]]; then
        WEBUI_CERT=$saved_wcert; WEBUI_KEY=$saved_wkey
    else
        install -d -m 700 $CONF_DIR/webui
        WEBUI_CERT=$CONF_DIR/webui/cert.pem; WEBUI_KEY=$CONF_DIR/webui/key.pem
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
            -subj "/CN=$PUBLIC_IP" -addext "subjectAltName=IP:$PUBLIC_IP" \
            -keyout "$WEBUI_KEY" -out "$WEBUI_CERT" >/dev/null 2>&1 \
            || die "Не удалось создать сертификат для веб-интерфейса"
    fi
    umask 077
    cat > $CONF_DIR/webui.env <<EOF
WEBUI_PORT=$WEBUI_PORT
WEBUI_CERT=$WEBUI_CERT
WEBUI_KEY=$WEBUI_KEY
EOF
    umask 022

    cat > /etc/systemd/system/l2tp-exit-web.service <<EOF
[Unit]
Description=l2tp-exit web UI (tunnel settings)
After=network-online.target

[Service]
EnvironmentFile=$CONF_DIR/webui.env
ExecStart=/usr/bin/python3 /usr/local/lib/l2tp-exit/webui.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable l2tp-exit-web >/dev/null 2>&1
    systemctl restart l2tp-exit-web
    sleep 2
    systemctl is-active --quiet l2tp-exit-web \
        || warn "Веб-интерфейс не запустился: journalctl -u l2tp-exit-web -n 30"

    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
        ufw allow "$WEBUI_PORT/tcp" >/dev/null
    fi
    # Сертификат домена из /root/cert/<домен>/ — показываем адрес по этому домену
    webui_host=$PUBLIC_IP
    [[ $WEBUI_CERT == /root/cert/*/fullchain.pem ]] && webui_host=$(basename "$(dirname "$WEBUI_CERT")")
    WEBUI_URL="https://$webui_host:$WEBUI_PORT/"
    [[ $(passwd -S root 2>/dev/null | awk '{print $2}') == P ]] \
        || warn "У root не задан пароль (вход только по ключу) — войти в веб-интерфейс не получится. Задайте его: passwd"
else
    systemctl disable --now l2tp-exit-web >/dev/null 2>&1 || true
fi

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
    echo "  Транспорт: $TRANSPORT"
    echo "  SNI      : $REALITY_SNI"
    echo "  PubKey   : $PBK"
    echo "  ShortId  : $SID"
    echo
    echo "  $VLESS_LINK"
    echo
    if [[ -n $EXIT_LINKS ]]; then
        echo "  Дополнительные выходы:"
        while read -r l; do echo "  $l"; done <<<"$EXIT_LINKS"
        echo
    fi
    if [[ -n $SUB_URL ]]; then
        echo "  Подписка (HTTPS, для Happ и др.):"
        echo "  $SUB_URL"
        echo
    fi
    if [[ $L2TP_SERVER == 1 ]]; then
        echo "================ L2TP/IPsec (Windows, macOS, iOS, роутеры) ================"
        echo "  Сервер   : $PUBLIC_IP"
        echo "  IPsec PSK: $L2TP_PSK"
        echo "  Логин    : $L2TP_USER"
        echo "  Пароль   : $L2TP_PASSWORD"
        echo "  (Android 12+ не умеет L2TP — для него ссылка VLESS выше. Windows за NAT:"
        echo "   нужен ключ реестра AssumeUDPEncapsulationContextOnSendRule=2, см. README)"
        echo
    fi
    if [[ -n $WEBUI_URL ]]; then
        echo "================ Веб-интерфейс туннеля ================"
        echo "  URL      : $WEBUI_URL"
        echo "  Вход     : root и его системный пароль"
        [[ -z $SUB_CERT && $WEBUI_CERT == $CONF_DIR/webui/* ]] \
            && echo "  (сертификат самоподписанный — браузер предупредит; с SUB_DOMAIN будет настоящий)"
        echo "  Здесь меняются сервер №2, режим при падении туннеля и DNS."
        echo
    fi
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
# QR подписки удобнее: Happ сам подтянет и будет обновлять конфиг
if [[ -n $SUB_URL ]]; then
    echo "QR подписки:"
    qrencode -t ansiutf8 "$SUB_URL" 2>/dev/null || true
else
    qrencode -t ansiutf8 "$VLESS_LINK" 2>/dev/null || true
fi
echo
log "Данные сохранены в $ACCESS_FILE"
