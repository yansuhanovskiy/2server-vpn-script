# VPN-каскад: 3x-ui → L2TP/IPsec → интернет

```
клиенты ──VLESS+Reality──┐
                         ├─▶ сервер №1 (3x-ui + L2TP) ──L2TP/IPsec──▶ сервер №2 (hwdsl2) ──▶ интернет
клиенты ──L2TP/IPsec─────┘
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
3. Ставит 3x-ui (закреплённая версия `v3.8.5`), создаёт inbound VLESS + Reality поверх XHTTP (порт 443).
4. Поднимает L2TP/IPsec сервер для устройств без VLESS-клиента: Windows, macOS, iOS, роутеры.
   Их трафик тоже уходит через сервер №2.
5. Печатает URL панели, логин и пароль, ссылку `vless://`, QR-код и данные L2TP.
   Всё это сохраняется в `/root/vpn-access.txt`.

**SNI (`REALITY_SNI`)** подбирается автоматически. ТСПУ режет Reality с «чужим» SNI вроде www.microsoft.com
на российском IP хостинга, поэтому нужен сайт из той же сети, что и сервер. Сначала скрипт смотрит таблицу
проверенных хостингов (для FirstVDS это `firstvds.ru`), затем сканирует соседние адреса в /24 и ищет сайт
с TLS 1.3, h2 и валидным сертификатом, домен которого указывает ровно на этот адрес. Если ничего не нашлось,
скрипт остановится и попросит указать `REALITY_SNI=домен` вручную. Все остальные шаги к этому моменту уже
выполнены, поэтому повторный запуск проходит быстро.

### Подписка по HTTPS (необязательно)
Happ и многие другие клиенты не принимают подписку по HTTP. Чтобы включить HTTPS, нужен домен
с A-записью на сервер №1. Если домен в Cloudflare, проксирование (оранжевое облако) должно быть выключено.
Передайте домен в переменной `SUB_DOMAIN`:

```bash
SUB_DOMAIN='vpn.example.com' VPN_SERVER_IP='...' VPN_IPSEC_PSK='...' VPN_USER='...' VPN_PASSWORD='...' \
  bash <(curl -fsSL https://raw.githubusercontent.com/yansuhanovskiy/2server-vpn-script/main/entry-server.sh)
```

Скрипт проверит, что домен указывает на сервер, получит сертификат Let's Encrypt через acme.sh
(на время проверки нужен свободный и открытый **порт 80**) и включит HTTPS для подписки и панели.
В конце он напечатает ссылку `https://домен:2096/sub/...` и её QR-код. Сертификат обновляется
автоматически. Если скрипт уже запускался без домена, повторный запуск с `SUB_DOMAIN` ничего
больше не меняет.

### L2TP/IPsec для клиентов
Сервер, PSK, логин и пароль печатаются в конце установки. Их можно задать заранее через `L2TP_PSK`,
`L2TP_USER` и `L2TP_PASSWORD`, а отключить L2TP можно через `L2TP_SERVER=0`.

- **Android 12+** больше не поддерживает L2TP, для него используйте ссылку VLESS.
- **Windows** по умолчанию не подключается к L2TP-серверу за NAT. Выполните один раз от администратора
  и перезагрузитесь:
  ```
  reg add HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent /v AssumeUDPEncapsulationContextOnSendRule /t REG_DWORD /d 2 /f
  ```
- Клиенты получают адреса `192.168.50.10–250`. DNS у них 1.1.1.1/8.8.8.8, и запросы идут через туннель.
- В файрволе провайдера сервера №1 должны быть открыты **UDP 500 и 4500**.

Необязательные переменные: `INBOUND_PORT`, `REALITY_SNI`, `TRANSPORT` (`xhttp`/`tcp`), `XUI_VERSION`,
`XUI_USERNAME`, `XUI_PASSWORD`, `XUI_PANEL_PORT`, `XUI_WEB_BASE_PATH`, `XUI_SSL_MODE` (`none`/`ip`/`domain`),
`L2TP_SERVER`, `L2TP_PSK`, `L2TP_USER`, `L2TP_PASSWORD`, `SUB_DOMAIN`, `KILL_SWITCH`, `DISABLE_IPV6`, `SET_DNS`.
Их описание есть в шапке скрипта.

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

### Диагностика
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yansuhanovskiy/2server-vpn-script/main/check-client.sh)
```
Эта команда проверяет ссылку из `/root/vpn-access.txt` прямо на сервере: временный Xray-клиент подключается
через неё и печатает внешний IP. Если проверка прошла, а на телефоне не работает, проблема в сети клиента (DPI).

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yansuhanovskiy/2server-vpn-script/main/test-variants.sh)
```
Этот скрипт создаёт тестовые inbound'ы с разными настройками (TCP+Vision, XHTTP, VLESS encryption) на портах
8443/9443/10443. Так можно подобрать вариант, который проходит через DPI провайдера.
