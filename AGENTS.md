# AGENTS.md — гайд для AI-агентов (Cursor Cloud / Composer)

## Проект

**PhantomProxy** — Go TCP-прокси с маскировкой MTProto под Fake TLS.

- Репозиторий: `github.com/RioTwWks/PhantomProxy`
- Модуль: `github.com/RioTwWks/PhantomProxy`
- Бинарник: `telegram-proxy` (`make build`)
- Точка входа: `cmd/proxy/main.go`

## Быстрый старт

```bash
make build && make run
# Прокси: :8443, WebUI: http://127.0.0.1:8081/ui/
make test
make integration
```

## Что читать перед изменениями

| Файл | Когда |
|------|-------|
| `docs/ARCHITECTURE.md` | Изменения в proxy/faketls/obfuscated2 |
| `docs/API.md` | Изменения в admin API или WebUI |
| `docs/CONFIG.md` | Новые поля конфигурации и env-переменные |
| `CONTRIBUTING.md` | Изменения в workflow разработки |
| `configs/config.yaml` | Пример конфигурации |
| `.cursorrules` | Общие соглашения проекта |

## Ключевые компоненты

```
cmd/proxy/main.go          → запуск proxy + admin
internal/proxy/server.go   → TCP accept, маршрутизация
internal/faketls/          → Fake TLS, JA3/JA4
internal/user/manager.go   → multi-user, thread-safe
internal/admin/server.go   → REST API
internal/admin/ui/         → WebUI (embed templates)
internal/runtime/          → Reload, UpdateSettings
```

## Типичные задачи

### Добавить поле в конфиг

1. Struct в `internal/config/config.go` (+ yaml/mapstructure теги)
2. Default в `loadFile()` если нужен
3. `SettingsView` в `settings.go` если редактируется из UI
4. Обновить `configs/config.yaml`, `docs/API.md`, README

### Добавить API-эндпоинт

1. Handler в `internal/admin/server.go`
2. Регистрация в `New()` с `withAuth` если нужен токен
3. Тест в `server_test.go`
4. Документация в `docs/API.md`

### Добавить страницу WebUI

1. Шаблон в `internal/admin/ui/templates/`
2. Handler в `internal/admin/ui/handler.go`
3. Регистрация маршрута в `Register()`
4. Тест в `handler_test.go`

## Ограничения

- **Не добавляй** Docker в CI без запроса (docker-compose уже есть для dev)
- **Не используй** Redis, Celery, внешние БД
- **Не меняй** `go.mod` без необходимости
- Management API слушает `127.0.0.1` — не открывай наружу без reverse proxy
- Комментарии в коде — на русском

## Ветки и PR

- Формат ветки: `cursor/<описание>-393e`
- Base branch: `main`
- Коммить и пушить перед созданием PR
- PR — draft по умолчанию

## MCP (локально в Cursor)

`.cursor/mcp.json` содержит:
- `filesystem` — файлы проекта
- `fetch` — тестирование API на `:8081`

## Тестирование изменений

```bash
# Unit
go test -race ./...

# Интеграция (mock DC)
go test -race -tags=integration ./internal/proxy/...

# Ручная проверка API
curl -H "Authorization: Bearer change-me-in-production" \
  http://127.0.0.1:8081/api/v1/status
```
