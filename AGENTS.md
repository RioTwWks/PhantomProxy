# AGENTS.md — гайд для AI-агентов (Cursor Cloud / Composer)

## Проект

**PhantomProxy** — Go TCP-прокси с маскировкой MTProto под Fake TLS + secure (`dd`).

- Репозиторий: `github.com/RioTwWks/PhantomProxy`
- Модуль: `github.com/RioTwWks/PhantomProxy`
- Бинарник: `telegram-proxy` (`make build`)
- Версия: `telegram-proxy version` → `0.2.0`
- Точка входа: `cmd/proxy/main.go`

## Быстрый старт

```bash
make build
./telegram-proxy run -config configs/config.yaml
# Прокси: :8443, WebUI: http://127.0.0.1:8081/ui/, Metrics: http://127.0.0.1:9090/metrics

GOTOOLCHAIN=local make test
GOTOOLCHAIN=local make integration
```

## Что читать перед изменениями

| Файл | Когда |
|------|-------|
| `docs/ROADMAP.md` | План фич, что в v2 отложено |
| `docs/ARCHITECTURE.md` | Потоки данных, пакеты |
| `docs/API.md` | REST API и WebUI |
| `docs/CONFIG.md` | YAML, env `PHANTOM_*` |
| `docs/DEPLOY.md` | systemd, nginx, Prometheus, SOCKS5 |
| `CONTRIBUTING.md` | Workflow, PR checklist |
| `configs/config.yaml` | Актуальный пример конфига |
| `.cursorrules` | Соглашения проекта |

## Ключевые компоненты

```
cmd/proxy/main.go           → CLI run/generate/version, proxy+admin+metrics
internal/proxy/server.go    → маршрутизация ee/dd, fronting, relay
internal/faketls/           → TLS, replay, splice, DRS, Split-TLS
internal/user/manager.go    → multi-user, JA3/JA4 whitelist, MatchSecure
internal/runtime/runtime.go → Reload, PersistUsers, Replay, Limiter
internal/metrics/           → Prometheus endpoint
internal/upstream/          → SOCKS5 + IPv prefer для DC
internal/limit/             → max connections per IP
internal/admin/             → REST + WebUI
```

## Типичные задачи

### Добавить поле в конфиг

1. Struct в `internal/config/config.go`
2. Default в `loadFile()`
3. `SettingsView` в `settings.go` (если в UI)
4. Обновить `configs/config.yaml`, `docs/CONFIG.md`

### Изменить логику прокси

1. `internal/proxy/server.go` — маршрутизация
2. Тест в `integration_test.go` (`-tags=integration`)
3. Обновить `docs/ARCHITECTURE.md` при смене потока

### CRUD пользователей

- API: `internal/admin/server.go` → `rt.PersistUsers()` после изменений
- UI: `internal/admin/ui/handler.go` → то же

### Добавить метрику Prometheus

1. Counter/Gauge в `internal/metrics/prometheus.go`
2. Инкремент из `proxy/server.go` или `runtime`
3. Документировать в `docs/DEPLOY.md`

## Ограничения

- Не добавляй Redis, БД, Celery
- Не меняй `go.mod` без необходимости; держи совместимость с Go 1.22
- Management API — только `127.0.0.1` в production
- Adtag / middle proxy — out of scope (см. ROADMAP v2)
- Комментарии в коде — на русском

## Ветки и PR

- Формат: `cursor/<описание>-393e`
- Base: `main`
- CI должен проходить: `GOTOOLCHAIN=local make test && make integration`

## MCP (локально в Cursor)

`.cursor/mcp.json`:
- `filesystem` — файлы проекта
- `fetch` — HTTP к `:8081` (API/WebUI) и `:9090` (metrics)

## Проверка после изменений

```bash
GOTOOLCHAIN=local make test
GOTOOLCHAIN=local make integration

curl -s http://127.0.0.1:8081/api/v1/health
curl -s -H "Authorization: Bearer change-me-in-production" \
  http://127.0.0.1:8081/api/v1/status
curl -s http://127.0.0.1:9090/metrics | head

./telegram-proxy generate www.google.com
```
