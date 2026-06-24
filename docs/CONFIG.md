# Справочник конфигурации PhantomProxy

Конфигурация загружается из YAML-файла (по умолчанию `configs/config.yaml`) и может быть переопределена переменными окружения с префиксом `PHANTOM_`.

Загрузчик: `internal/config/config.go` (Viper).

## Запуск

```bash
./telegram-proxy -config /path/to/config.yaml
```

Флаг `-config` по умолчанию: `configs/config.yaml`.

## Приоритет значений

1. Переменные окружения `PHANTOM_*` (высший приоритет)
2. Поля в YAML-файле
3. Значения по умолчанию из кода (если поле не задано)

## Полный пример YAML

```yaml
listen:
  host: "0.0.0.0"
  port: 8443

mtproto:
  backend: ""
  users:
    - name: alice
      secret: "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
      enabled: true
    - name: bob
      secret: "ee0123456789abcdef0123456789abcdef6578616d706c652e636f6d"
      enabled: false

tls:
  record_min_chunk: 512
  record_max_chunk: 4096
  noise_mean: 3000
  noise_jitter: 800
  allowed_ja3: []

fallback:
  upstream: "http://127.0.0.1:8080"

management:
  host: "127.0.0.1"
  port: 8081
  token: "change-me-in-production"
  public_server: ""
```

---

## Секции и поля

### `listen` — TCP-прокси

| Поле | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `host` | string | `0.0.0.0` | Адрес прослушивания MTProto-прокси |
| `port` | int | `443` | Порт прослушивания |

> Изменение `listen.host` / `listen.port` через API/UI записывается в файл, но **требует перезапуска процесса** для применения к TCP-listener.

**Env:** `PHANTOM_LISTEN_HOST`, `PHANTOM_LISTEN_PORT`

---

### `mtproto` — пользователи и бэкенд Telegram

| Поле | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `backend` | string | `""` | Адрес Telegram DC (`host:port`). Пусто — авто-резолв |
| `secret` | string | — | *(устаревшее)* один секрет; создаёт пользователя `default` |
| `users` | array | — | Список пользователей (рекомендуемый способ) |

#### `mtproto.users[]`

| Поле | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `name` | string | SNI из секрета | Уникальное имя пользователя |
| `secret` | string | **обязательно** | Hex- или base64-секрет Fake TLS (`ee` + 16 байт ключа + домен) |
| `enabled` | bool | `true` | Активен ли пользователь |

**Формат секрета:**

```
ee + <16 байт ключа> + <домен маскировки>
```

Пример hex: `ee367a18...676f6f676c65617069732e636f6d` → домен `storage.googleapis.com`.

Хотя бы один пользователь с `enabled: true` обязателен.

**Env:** `PHANTOM_MTPROTO_BACKEND`, `PHANTOM_MTPROTO_SECRET`

> Массив `mtproto.users` задаётся в YAML или через API/WebUI. Переопределение списка пользователей через env не поддерживается.

---

### `tls` — Fake TLS и отпечатки

| Поле | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `record_min_chunk` | int | `512` | Минимальный размер TLS Application Data (байт) |
| `record_max_chunk` | int | `4096` | Максимальный размер TLS Application Data (байт) |
| `noise_mean` | int | `3000` | Средний размер padding в ServerHello |
| `noise_jitter` | int | `800` | Разброс padding ServerHello |
| `allowed_ja3` | []string | `[]` | Белый список JA3-отпечатков; пусто — все разрешены |

**Env:**

| Переменная | YAML-ключ |
|------------|-----------|
| `PHANTOM_TLS_RECORD_MIN_CHUNK` | `tls.record_min_chunk` |
| `PHANTOM_TLS_RECORD_MAX_CHUNK` | `tls.record_max_chunk` |
| `PHANTOM_TLS_NOISE_MEAN` | `tls.noise_mean` |
| `PHANTOM_TLS_NOISE_JITTER` | `tls.noise_jitter` |
| `PHANTOM_TLS_ALLOWED_JA3` | `tls.allowed_ja3` |

Для `allowed_ja3` в env можно попробовать comma-separated значения; надёжнее задавать в YAML.

---

### `fallback` — сайт-заглушка

| Поле | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `upstream` | string | `http://127.0.0.1:8080` | HTTP upstream для не-MTProto соединений |

**Env:** `PHANTOM_FALLBACK_UPSTREAM`

---

### `management` — REST API и WebUI

| Поле | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `host` | string | `127.0.0.1` | Адрес HTTP-сервера управления |
| `port` | int | `8081` | Порт API/WebUI; `0` — отключить management |
| `token` | string | `""` | Токен API; пустой — без аутентификации |
| `public_server` | string | `""` | Публичный IP/домен для tg:// ссылок в UI/API |

**Env:**

| Переменная | YAML-ключ |
|------------|-----------|
| `PHANTOM_MANAGEMENT_HOST` | `management.host` |
| `PHANTOM_MANAGEMENT_PORT` | `management.port` |
| `PHANTOM_MANAGEMENT_TOKEN` | `management.token` |
| `PHANTOM_MANAGEMENT_PUBLIC_SERVER` | `management.public_server` |

> В production: смени `token`, не публикуй management наружу без reverse proxy с TLS.

---

## Таблица переменных окружения

Правило именования: `PHANTOM_` + путь в YAML, где `.` заменяется на `_`, в верхнем регистре.

| Переменная | Тип | Пример |
|------------|-----|--------|
| `PHANTOM_LISTEN_HOST` | string | `0.0.0.0` |
| `PHANTOM_LISTEN_PORT` | int | `443` |
| `PHANTOM_MTPROTO_BACKEND` | string | `149.154.167.99:443` |
| `PHANTOM_MTPROTO_SECRET` | string | `ee0123...` |
| `PHANTOM_TLS_RECORD_MIN_CHUNK` | int | `512` |
| `PHANTOM_TLS_RECORD_MAX_CHUNK` | int | `4096` |
| `PHANTOM_TLS_NOISE_MEAN` | int | `3000` |
| `PHANTOM_TLS_NOISE_JITTER` | int | `800` |
| `PHANTOM_TLS_ALLOWED_JA3` | string[] | `abc,def` |
| `PHANTOM_FALLBACK_UPSTREAM` | string | `http://nginx:80` |
| `PHANTOM_MANAGEMENT_HOST` | string | `127.0.0.1` |
| `PHANTOM_MANAGEMENT_PORT` | int | `8081` |
| `PHANTOM_MANAGEMENT_TOKEN` | string | `my-secret-token` |
| `PHANTOM_MANAGEMENT_PUBLIC_SERVER` | string | `proxy.example.com` |

### Пример Docker Compose

```yaml
services:
  proxy:
    environment:
      PHANTOM_LISTEN_PORT: "8443"
      PHANTOM_FALLBACK_UPSTREAM: "http://web:80"
      PHANTOM_MANAGEMENT_TOKEN: "${MANAGEMENT_TOKEN}"
      PHANTOM_MANAGEMENT_PUBLIC_SERVER: "203.0.113.10"
```

---

## Изменение конфигурации в runtime

| Способ | Что обновляет | Перезапуск |
|--------|---------------|------------|
| `POST /api/v1/reload` | Перечитывает YAML с диска | Нет |
| `PUT /api/v1/config` | Настройки + запись в файл | Нет* |
| CRUD `/api/v1/users` | Пользователи в памяти | Нет |
| WebUI `/ui/settings` | То же, что `PUT /api/v1/config` | Нет* |
| Редактирование YAML вручную + reload | Всё из файла | Нет |

\* Кроме `listen.host` / `listen.port` — для них нужен перезапуск процесса.

Файл конфигурации при сохранении через API записывается с правами `0600`.

---

## Обратная совместимость

Если `mtproto.users` не задан, но указан `mtproto.secret`:

```yaml
mtproto:
  secret: "ee0123456789abcdef..."
```

будет создан один пользователь с именем `default`.

---

## Типичные сценарии

### Production на VPS

```yaml
listen:
  host: "0.0.0.0"
  port: 443

management:
  host: "127.0.0.1"      # только localhost; снаружи — через SSH tunnel / nginx
  port: 8081
  token: "<случайный-токен>"
  public_server: "203.0.113.10"

fallback:
  upstream: "http://127.0.0.1:8080"
```

### Локальная разработка

Используй `configs/config.yaml` из репозитория (`port: 8443`) и `docker compose up` для nginx-заглушки.

### Секрет через env (один пользователь)

```bash
export PHANTOM_MTPROTO_SECRET="ee0123456789abcdef0123456789abcdef6578616d706c652e636f6d"
./telegram-proxy -config configs/config.yaml
```

В YAML при этом `mtproto.users` можно не указывать.

---

## См. также

- [API.md](API.md) — REST API для управления конфигом
- [ARCHITECTURE.md](ARCHITECTURE.md) — как настройки влияют на поток данных
