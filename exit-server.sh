#!/bin/bash
#
# exit-server.sh — сервер №2 (выходной узел).
#
# Ставит L2TP/IPsec сервер через https://github.com/hwdsl2/setup-ipsec-vpn
# и печатает готовую команду для запуска entry-server.sh на сервере №1.
#
# Переменные окружения (все необязательные):
#   VPN_IPSEC_PSK   — PSK для IPsec          (по умолчанию: случайный)
#   VPN_USER        — логин L2TP             (по умолчанию: relay)
#   VPN_PASSWORD    — пароль L2TP            (по умолчанию: случайный)
#   VPN_SKIP_IKEV2  — не ставить IKEv2       (по умолчанию: yes)
#
# При повторном запуске без переменных переиспользуются ранее сгенерированные
# данные из /root/l2tp-exit-credentials.env.

set -euo pipefail

CRED_FILE=/root/l2tp-exit-credentials.env
REPO_RAW=https://raw.githubusercontent.com/yansuhanovskiy/2server-vpn-script/main

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; plain='\033[0m'
log()  { echo -e "${green}==>${plain} $*"; }
warn() { echo -e "${yellow}WARN:${plain} $*" >&2; }
die()  { echo -e "${red}ERROR:${plain} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Запустите от root."

# Без head: head закрывает pipe раньше времени, и pipefail валит скрипт
rand() {
    local s
    s=$(openssl rand -base64 96 | tr -dc 'A-Za-z0-9')
    printf '%s' "${s:0:$1}"
}

command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl; }
command -v openssl >/dev/null || { apt-get update -qq && apt-get install -y -qq openssl; }

if [[ -f $CRED_FILE ]]; then
    # shellcheck disable=SC1090
    saved_psk=$(. "$CRED_FILE"; echo "$VPN_IPSEC_PSK")
    saved_user=$(. "$CRED_FILE"; echo "$VPN_USER")
    saved_pass=$(. "$CRED_FILE"; echo "$VPN_PASSWORD")
fi

VPN_IPSEC_PSK=${VPN_IPSEC_PSK:-${saved_psk:-$(rand 24)}}
VPN_USER=${VPN_USER:-${saved_user:-relay}}
VPN_PASSWORD=${VPN_PASSWORD:-${saved_pass:-$(rand 20)}}
VPN_SKIP_IKEV2=${VPN_SKIP_IKEV2:-yes}

for v in "$VPN_IPSEC_PSK" "$VPN_USER" "$VPN_PASSWORD"; do
    [[ $v =~ [\\\"\'] ]] && die "Логин/пароль/PSK не должны содержать символы \\ \" '"
done

export VPN_IPSEC_PSK VPN_USER VPN_PASSWORD VPN_SKIP_IKEV2

log "Скачиваю и запускаю hwdsl2/setup-ipsec-vpn ..."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 https://get.vpnsetup.net -o "$tmp/vpn.sh" \
    || curl -fsSL --retry 3 https://raw.githubusercontent.com/hwdsl2/setup-ipsec-vpn/master/vpnsetup.sh -o "$tmp/vpn.sh" \
    || die "Не удалось скачать vpnsetup.sh"
sh "$tmp/vpn.sh"

PUBLIC_IP=${VPN_PUBLIC_IP:-}
if [[ -z $PUBLIC_IP ]]; then
    for u in https://ipv4.icanhazip.com https://api4.ipify.org https://4.ident.me; do
        PUBLIC_IP=$(curl -4 -fsS --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]') || true
        [[ $PUBLIC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && break
        PUBLIC_IP=""
    done
fi
[[ -n $PUBLIC_IP ]] || { warn "Не удалось определить публичный IP, подставьте его вручную."; PUBLIC_IP="<IP_ЭТОГО_СЕРВЕРА>"; }

umask 077
cat > "$CRED_FILE" <<EOF
VPN_SERVER_IP='$PUBLIC_IP'
VPN_IPSEC_PSK='$VPN_IPSEC_PSK'
VPN_USER='$VPN_USER'
VPN_PASSWORD='$VPN_PASSWORD'
EOF

echo
echo -e "${green}================ Выходной L2TP/IPsec сервер готов ================${plain}"
echo "  IP сервера : $PUBLIC_IP"
echo "  IPsec PSK  : $VPN_IPSEC_PSK"
echo "  Логин      : $VPN_USER"
echo "  Пароль     : $VPN_PASSWORD"
echo
echo "  Данные сохранены в $CRED_FILE"
echo
echo "  Убедитесь, что в файрволе провайдера открыты UDP 500 и UDP 4500."
echo
echo -e "${green}Команда для сервера №1 (входного):${plain}"
echo
echo "  VPN_SERVER_IP='$PUBLIC_IP' VPN_IPSEC_PSK='$VPN_IPSEC_PSK' VPN_USER='$VPN_USER' VPN_PASSWORD='$VPN_PASSWORD' bash <(curl -fsSL $REPO_RAW/entry-server.sh)"
echo
