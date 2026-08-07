# Relay Front/Back (РФ → EU)

Зашифрованный туннель между двумя PhantomProxy: клиенты подключаются только к **Front (РФ)**, выход в Telegram — с **Back (EU)**.

## Схема

```
Telegram (MTProto) → Front RU :443 → relay PHRP/AES-GCM → Back EU :9443 → Middle Proxy / DC
```

## Быстрый старт

### 1. Общий PSK (одинаковый на обоих серверах)

```bash
openssl rand -hex 32
```

Вставь значение в `relay.psk` в обоих конфигах.

### 2. EU Back

```bash
# configs/config.eu.yaml — relay.mode: back, relay.listen_port: 9443
# middle_proxy_nat_ip: публичный IPv4 EU-сервера
make build
./telegram-proxy run -config configs/config.eu.yaml
```

Открой порт **9443** только для IP RU Front (firewall):

```bash
ufw allow from RU_FRONT_IP to any port 9443 proto tcp
```

### 3. RU Front

```bash
# Сгенерируй секрет с правдоподобным SNI
./telegram-proxy generate microsoft.com

# Вставь secret в configs/config.ru.yaml
# relay.peer_addr: "EU_SERVER_IP:9443"
./telegram-proxy run -config configs/config.ru.yaml
```

В Telegram: **Настройки → Прокси → MTProto** — IP RU Front, порт 443, секрет `ee...`.

## Конфигурация relay

| Поле | Front (RU) | Back (EU) |
|------|------------|-----------|
| `relay.mode` | `front` | `back` |
| `relay.peer_addr` | `EU_IP:9443` | — |
| `relay.listen_port` | — | `9443` |
| `relay.psk` | hex 32+ байт | тот же |

## Протокол PHRP

1. TCP connect Front→Back
2. Handshake: `PHRP` + nonce(16) + HMAC-SHA256(psk, nonce)(32) + dcID(2)
3. Фреймы: `[4 byte len][AES-GCM ciphertext]`

## Рекомендации

- RU Front: `fallback.honeypot: true`, `fronting.action: splice`
- EU Back: `use_middle_proxy: true` + `ad_tag` от @MTProxybot
- Мониторинг: `phantom_tls_reject_reason_total`, `phantom_probe_requests_total`

Примеры конфигов: `configs/config.ru.yaml`, `configs/config.eu.yaml`.
