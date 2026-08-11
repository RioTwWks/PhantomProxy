# Relay Front/Back (РФ → EU)

Зашифрованный туннель между двумя PhantomProxy: клиенты подключаются только к **Front (РФ)**, выход в Telegram — с **Back (EU)**.

## Схема

```
Telegram (MTProto) → Front RU :15443 → relay PHRP/AES-GCM → Back EU :15443 → Middle Proxy / DC
```

## Быстрый старт

### 1. Общий PSK (одинаковый на обоих серверах)

```bash
openssl rand -hex 32
```

Вставь значение в `relay.psk` в обоих конфигах.

### 2. EU Back

```bash
# configs/config.eu.yaml — relay.mode: back, relay.listen_port: 15443
# middle_proxy_nat_ip: публичный IPv4 EU-сервера
make build
./telegram-proxy run -config configs/config.eu.yaml
```

Открой порт **15443** только для IP RU Front (firewall):

```bash
ufw allow from RU_FRONT_IP to any port 15443 proto tcp
```

### 3. RU Front

```bash
# Сгенерируй секрет с правдоподобным SNI
./telegram-proxy generate microsoft.com

# Скопируй и отредактируй конфиг (замени ВСЕ placeholder-строки!)
sudo cp configs/config.ru.yaml /etc/phantomproxy/config.yaml
sudo nano /etc/phantomproxy/config.yaml
# secret, relay.peer_addr, management.public_server, management.token

# Проверка перед запуском
./telegram-proxy check -config /etc/phantomproxy/config.yaml

# Установка сервиса
make install-service
```

> **Важно:** если оставить `eeREPLACE_WITH_GENERATED_SECRET` или `EU_SERVER_IP` — systemd unit будет падать с `status=1/FAILURE`. Ошибка видна в `journalctl`, не в `systemctl status`.

В Telegram: **Настройки → Прокси → MTProto** — IP RU Front, порт **15443**, секрет `ee...`.

## Конфигурация relay

| Поле | Front (RU) | Back (EU) |
|------|------------|-----------|
| `relay.mode` | `front` | `back` |
| `relay.peer_addr` | `EU_IP:15443` | — |
| `relay.listen_port` | — | `15443` |
| `relay.psk` | hex 32+ байт | тот же |

## Протокол PHRP

1. TCP connect Front→Back
2. Handshake: `PHRP` + nonce(16) + HMAC-SHA256(psk, nonce)(32) + dcID(2) + clientIPv4(4) + clientPort(2)
3. Фреймы: `[4 byte len][AES-GCM ciphertext]`

## Рекомендации

- RU Front: `fallback.honeypot: true`, `fronting.action: splice`
- EU Back: `use_middle_proxy: true` + `ad_tag` от @MTProxybot
- Мониторинг: `phantom_tls_reject_reason_total`, `phantom_probe_requests_total`

Примеры конфигов: `configs/config.ru.yaml`, `configs/config.eu.yaml`.

## Диагностика «ничего не происходит»

Если при подключении из Telegram в логах **только старт**, без строк `входящее соединение`:

1. **Порт не открыт снаружи** — проверь firewall хостера (панель VPS) и `iptables`/`ufw` на RU:
   ```bash
   ss -tlnp | grep 15443
   nc -zv 37.9.4.136 15443   # с другого сервера или телефона (не Wi‑Fi дома)
   ```
2. **Нестандартный порт** — мобильные операторы в РФ часто режут не-443. Попробуй `listen.port: 443` на RU (если порт свободен).
3. **Неверная ссылка** — IP, порт и секрет должны совпадать:
   ```
   tg://proxy?server=RU_PUBLIC_IP&port=15443&secret=ee...
   ```

Если `входящее соединение` есть, но нет `клиент подключён`:

```bash
./telegram-proxy run -config configs/config.ru.yaml -log-level debug
```

Смотри `fake TLS отклонён` — неверный секрет, replay, JA3 whitelist и т.д.

Если RU подключает клиента, но EU молчит:

```bash
# с RU-сервера
nc -zv 212.192.215.248 15443
```

На EU должен быть открыт **15443 только с IP RU** (`37.9.4.136`). В логах EU: `relay back: входящее соединение`.

### RU подключает клиента, EU только `handshake ok`, нет `relay back подключён`

Цепочка RU→EU работает, но EU **не выходит в Telegram DC**. На RU: `upload>0 download=0`.

1. На EU включи debug и смотри ошибку (с версии с логированием):
   ```
   relay back: не удалось подключиться к DC ... err=...
   ```
2. **Проверь исходящий доступ с EU** к middle proxy Telegram:
   ```bash
   nc -zv 149.154.161.144 8888   # DC2
   ```
3. **`middle_proxy_nat_ip`** — публичный IPv4 EU-сервера (`212.192.215.248`), не RU. Должен совпадать с IP, с которого EU ходит в интернет.
4. **`ad_tag`** — получи у @MTProxybot и раскомментируй в `config.eu.yaml`.
5. **Быстрый тест без ME** — временно на EU:
   ```yaml
   mtproto:
     use_middle_proxy: false
   ```
   Перезапусти EU. Если появится `relay back подключён` — проблема в middle proxy / firewall :8888.

### EU «тишина», на RU нет `клиент подключён`

Если на EU только `relay back слушает`, а на RU **нет** строк `клиент подключён` — до EU трафик **не доходит**. Сначала чини RU.

1. **Probe blacklist** — после 8 неудач IP `185.210.143.32` блокируется на 2 часа. В логе: `соединение отклонено: IP в probe blacklist`. Решение: перезапуск RU или `probe_blacklist_threshold: 50`.
2. **Версии RU и EU** — оба сервера должны быть с одного коммита (PR #25). Иначе ищи на RU `relay front ошибка`.
3. **Проверка RU→EU** с RU-сервера: `nc -zv 212.192.215.248 15443`

### Probe blacklist на RU

После серии неудач IP клиента блокируется (`IP в probe blacklist`). **Перезапусти** `./telegram-proxy` или подними `probe_blacklist_threshold` на время отладки.

Полезные метрики: `curl -s http://127.0.0.1:9090/metrics | grep phantom_`
