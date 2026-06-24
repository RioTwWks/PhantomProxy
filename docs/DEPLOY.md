# Деплой PhantomProxy

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

Для выхода в Telegram DC через туннель:

```yaml
upstream:
  socks5: "127.0.0.1:1080"
```

## Генерация секретов

```bash
./telegram-proxy generate www.google.com
```
