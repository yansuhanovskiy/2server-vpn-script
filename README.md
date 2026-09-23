# VPN-каскад: 3x-ui → L2TP/IPsec → интернет

```
клиенты ──VLESS+Reality──▶ сервер №1 (3x-ui) ──L2TP/IPsec──▶ сервер №2 (hwdsl2) ──▶ интернет
```

Поддерживаются Debian 11+ и Ubuntu 22.04+.

## 1. Сервер №2 (выходной)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yansuhanovskiy/2server-vpn-script/main/exit-server.sh)
```

Скрипт ставит [hwdsl2/setup-ipsec-vpn](https://github.com/hwdsl2/setup-ipsec-vpn), IKEv2 не ставит
(чтобы поставить, запустите с `VPN_SKIP_IKEV2=no`). В конце он печатает готовую команду для сервера №1.
Данные доступа сохраняются в `/root/l2tp-exit-credentials.env`.
В файрволе провайдера должны быть открыты **UDP 500 и 4500**.

## 2. Сервер №1 (входной)

Выполните команду, которую напечатал сервер №2:

```bash
VPN_SERVER_IP='1.2.3.4' VPN_IPSEC_PSK='...' VPN_USER='relay' VPN_PASSWORD='...' \
  bash <(curl -fsSL https://raw.githubusercontent.com/yansuhanovskiy/2server-vpn-script/main/entry-server.sh)
```

Что делает скрипт:
1. Настраивает L2TP/IPsec клиент (strongSwan swanctl + xl2tpd) и сервис `l2tp-exit`, который следит за туннелем и переподключает его.
2. Настраивает policy routing: весь исходящий трафик идёт в туннель, а ответы на входящие
   соединения (SSH, клиенты, панель) уходят напрямую, поэтому SSH не отваливается.
3. Ставит 3x-ui в неинтерактивном режиме, создаёт inbound VLESS + Reality (порт 443) и печатает
   URL панели, логин и пароль, ссылку `vless://` и QR-код. Всё это сохраняется в `/root/vpn-access.txt`.

Необязательные переменные: `INBOUND_PORT`, `REALITY_SNI`, `XUI_USERNAME`, `XUI_PASSWORD`,
`XUI_PANEL_PORT`, `XUI_WEB_BASE_PATH`, `XUI_SSL_MODE` (`none`/`ip`/`domain`), `KILL_SWITCH`,
`DISABLE_IPV6`, `SET_DNS`. Их описание есть в шапке скрипта.

### Что по умолчанию меняется на сервере №1
- **Kill switch** (`KILL_SWITCH=1`): если туннель упал, сервер не выходит в интернет напрямую.
  Входящие соединения и связь с сервером №2 продолжают работать.
- **IPv6 выключен** (`DISABLE_IPV6=1`): туннель работает только по IPv4, и без этого Xray мог бы ходить по IPv6 в обход туннеля.
- **DNS** (`SET_DNS=1`): `/etc/resolv.conf` указывает на 1.1.1.1/8.8.8.8, запросы идут через туннель.
  Оригинал сохраняется в `/etc/resolv.conf.l2tp-exit.bak`.

### Управление
```bash
l2tp-exit status                              # SA, ppp, правила, внешний IP
journalctl -u l2tp-exit -f                    # лог переподключений
l2tp-exit down && systemctl disable l2tp-exit # выключить туннель и вернуть маршрутизацию
```
