# Деплой PhantomProxy

## Быстрая установка (одна команда)

```bash
make install-service
# или: make build && sudo bash deploy/install.sh --no-build
```

`make install-service` сначала собирает бинарь **от твоего пользователя** (где `go` в PATH), затем вызывает `sudo` только для установки.

Если запускаешь `sudo bash deploy/install.sh` напрямую, скрипт попытается собрать от пользователя, вызвавшего `sudo` (`$SUDO_USER`). Если Go не установлен — сначала `make build`, потом `sudo bash deploy/install.sh --no-build`.

> **Важно:** `PHANTOM_SKIP_BUILD=1 sudo ...` не работает — `sudo` по умолчанию не передаёт переменные окружения. Используй флаг `--no-build`.

Скрипт создаст пользователя `phantom`, установит файлы в `/opt/phantomproxy` и `/etc/phantomproxy`, включит systemd unit.

## Удаление (одна команда)

```bash
sudo make uninstall-service
# или
sudo bash deploy/uninstall.sh
```

Полное удаление с конфигом и бинарником:

```bash
sudo bash deploy/uninstall.sh --purge
```

Docker Compose:

```bash
sudo bash deploy/uninstall.sh --docker
```

### Удаление через WebUI

В `config.yaml` включи:

```yaml
management:
  allow_service_uninstall: true
  uninstall_script: /opt/phantomproxy/uninstall.sh
```

На странице **Настройки** появится блок «Опасная зона» — введи `УДАЛИТЬ` и нажми кнопку.

### Удаление через API

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"confirm":"УДАЛИТЬ","purge":false}' \
  http://127.0.0.1:8081/api/v1/service/uninstall
```

### CLI

```bash
./telegram-proxy uninstall
./telegram-proxy uninstall --purge
```

## Сборка

```bash
make build
sudo install -m 755 telegram-proxy /opt/phantomproxy/
sudo install -m 600 configs/config.yaml /etc/phantomproxy/config.yaml
```

## systemd

```bash
sudo useradd -r -s /usr/sbin/nologin phantom || true
sudo cp deploy/phantom-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now phantom-proxy
```

Проверка:

```bash
curl -s http://127.0.0.1:8081/api/v1/health
curl -s http://127.0.0.1:9090/metrics | head
```

## Устранение неполадок

Запусти на проблемном сервере:

```bash
sudo bash /opt/phantomproxy/diagnose.sh
# или из репозитория:
sudo bash deploy/diagnose.sh
```

Скрипт проверит права, валидность конфига, занятость портов и выведет логи systemd.

### Сервис падает с `status=1/FAILURE` сразу после старта

**1. Посмотри реальную ошибку** (в `systemctl status` её нет — только код выхода):

```bash
sudo journalctl -u phantom-proxy -n 30 --no-pager
# или
sudo -u phantom /opt/phantomproxy/telegram-proxy check -config /etc/phantomproxy/config.yaml
```

**2. Нет доступа к конфигу** (`permission denied`):

```bash
sudo chown -R phantom:phantom /etc/phantomproxy
sudo chmod 750 /etc/phantomproxy
sudo chmod 600 /etc/phantomproxy/config.yaml
sudo systemctl restart phantom-proxy
```

**3. Невалидный конфиг на RU Front** (частый случай при `configs/config.ru.yaml`):

Если в `/etc/phantomproxy/config.yaml` остались placeholder-строки (`REPLACE_WITH`, `EU_SERVER_IP`, `CHANGE-ME`), сервис падает с `ошибка загрузки конфигурации`.

```bash
# сгенерируй секрет
./telegram-proxy generate microsoft.com
# вставь ee_secret в mtproto.users[].secret
# укажи relay.peer_addr, management.public_server
sudo nano /etc/phantomproxy/config.yaml
sudo -u phantom /opt/phantomproxy/telegram-proxy check -config /etc/phantomproxy/config.yaml
sudo systemctl restart phantom-proxy
```

См. также `docs/RELAY.md`.

**4. Порт занят** (`address already in use`):

```bash
sudo ss -tlnp | grep -E '8443|15443|8081|9090'
```

На RU Front обычно `listen.port: 15443` (или `443`). На EU Back — `relay.listen_port: 15443` плюс `management`/`metrics` на `8081`/`9090`. Если на сервере уже крутится Prometheus — смени `metrics.port` или отключи (`port: 0`).

Проверка вручную:

```bash
sudo -u phantom /opt/phantomproxy/telegram-proxy run -config /etc/phantomproxy/config.yaml
```

## Docker Compose

```bash
docker compose up --build -d
```

Переменная `PHANTOM_FALLBACK_UPSTREAM=http://web:80` уже задана в `docker-compose.yml`.

## За reverse proxy (nginx + PROXY protocol)

```yaml
listen:
  proxy_protocol: true
```

nginx:

```nginx
stream {
    server {
        listen 443;
        proxy_pass 127.0.0.1:8443;
        proxy_protocol on;
    }
}
```

## Prometheus

По умолчанию метрики на `127.0.0.1:9090/metrics`. Для Grafana добавь scrape target.

## SOCKS5 upstream

Для выхода в Telegram DC через туннель (только **direct mode**, не middle proxy):

```yaml
upstream:
  socks5: "127.0.0.1:1080"
```

## Middle proxy и adtag

Для промо-канала (@MTProxybot) и медиа у non-Premium:

```yaml
mtproto:
  ad_tag: "0123456789abcdef0123456789abcdef"
  use_middle_proxy: true
  middle_proxy_nat_ip: "1.2.3.4"   # публичный IPv4 (обязательно за NAT)
```

При наличии `ad_tag` middle proxy включается автоматически.

> SOCKS5 и middle proxy одновременно не работают — прокси переключится на direct.

## Генерация секретов

```bash
./telegram-proxy generate www.google.com
```
