# REST API PhantomProxy

Базовый URL: `http://<management.host>:<management.port>`

По умолчанию: `http://127.0.0.1:8081`

## Аутентификация

Все эндпоинты, кроме `/api/v1/health`, требуют токен из `management.token`.

Способы передачи:

```http
Authorization: Bearer change-me-in-production
```

или

```http
X-API-Token: change-me-in-production
```

Если `management.token` пустой, аутентификация отключена (не рекомендуется в production).

## Формат ответов

Успех — JSON с `Content-Type: application/json; charset=utf-8`.

Ошибка:

```json
{"error": "описание ошибки"}
```

## Эндпоинты

### `GET /api/v1/health`

Проверка доступности. **Без аутентификации.**

```json
{"status": "ok"}
```

---

### `GET /api/v1/status`

Сводка состояния прокси.

```json
{
  "uptime_seconds": 3600,
  "listen_addr": "0.0.0.0:8443",
  "mask_host": "storage.googleapis.com",
  "backend": "",
  "users_count": 2,
  "active_connections": 3,
  "total_connections": 150,
  "upload_bytes": 1048576,
  "download_bytes": 2097152
}
```

---

### `GET /api/v1/users`

Список пользователей с tg:// ссылками.

Query-параметры (опционально):
- `server` — хост для ссылок (переопределяет `public_server`)
- `port` — порт для ссылок

```json
{
  "users": [
    {
      "name": "alice",
      "enabled": true,
      "secret": "ee367a18...",
      "mask_host": "storage.googleapis.com",
      "tg_link": "tg://proxy?server=1.2.3.4&port=8443&secret=ee..."
    }
  ]
}
```

### `POST /api/v1/users`

Создание пользователя.

```json
{
  "name": "charlie",
  "secret": "",
  "host": "example.com",
  "enabled": true
}
```

- `secret` — hex-секрет MTProto; если пустой, генерируется автоматически с маской `host`
- `host` — домен для SNI в сгенерированном секрете (используется только при автогенерации)

Ответ `201 Created` — объект пользователя (как в `GET /api/v1/users/{name}`).

### `GET /api/v1/users/{name}`

Получить одного пользователя.

### `PUT /api/v1/users/{name}`

Обновление пользователя.

```json
{
  "secret": "ee...",
  "enabled": false
}
```

Поля опциональны: можно обновить только `enabled` или только `secret`.

### `DELETE /api/v1/users/{name}`

Удаление пользователя. Ответ `204 No Content`.

---

### `GET /api/v1/stats`

Общая статистика.

```json
{
  "active_connections": 2,
  "total_connections": 100,
  "upload_bytes": 500000,
  "download_bytes": 1200000,
  "users": {
    "alice": {
      "active_connections": 1,
      "total_connections": 50,
      "upload_bytes": 250000,
      "download_bytes": 600000
    }
  }
}
```

### `GET /api/v1/stats/{name}`

Статистика конкретного пользователя.

---

### `POST /api/v1/reload`

Перечитывает `config.yaml` с диска (пользователи + настройки).

```json
{"status": "reloaded"}
```

Активные соединения не разрываются; новые настройки применяются к новым соединениям.

---

### `GET /api/v1/config`

Текущие настройки (без списка пользователей).

```json
{
  "listen_host": "0.0.0.0",
  "listen_port": 8443,
  "backend": "",
  "fallback_upstream": "http://127.0.0.1:8080",
  "record_min_chunk": 512,
  "record_max_chunk": 4096,
  "noise_mean": 3000,
  "noise_jitter": 800,
  "allowed_ja3": [],
  "public_server": ""
}
```

### `PUT /api/v1/config`

Обновляет настройки и **сохраняет** их в файл конфигурации.

Тело — тот же формат, что и `GET /api/v1/config`.

> Изменение `listen_port` / `listen_host` записывается в конфиг, но для применения к TCP-листенеру нужен перезапуск процесса.

---

## WebUI

WebUI использует те же данные, что и API, но через HTML-шаблоны и HTMX.

| Маршрут | Описание |
|---------|----------|
| `/ui/` | Дашборд со статистикой |
| `/ui/users` | Управление пользователями |
| `/ui/settings` | Настройки прокси |
| `/ui/login` | Вход по токену |
| `/ui/partials/stats` | HTMX-фрагмент карточек статистики |
| `/ui/partials/users-stats` | HTMX-фрагмент таблицы по пользователям |

Сессия хранится в cookie `phantom_session`.

## Примеры curl

```bash
TOKEN="change-me-in-production"

# Статус
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/api/v1/status | jq

# Создать пользователя
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","host":"google.com"}' \
  http://127.0.0.1:8081/api/v1/users | jq

# Перезагрузить конфиг
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8081/api/v1/reload
```
