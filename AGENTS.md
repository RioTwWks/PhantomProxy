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

GOTOOLCHAIN=local make ci          # test + integration + build
GOTOOLCHAIN=local make fuzz        # fuzz 30s
```

## Что читать перед изменениями

| Файл | Когда |
|------|-------|
| `docs/ROADMAP.md` | План фич, Phase 5 (v2) и отложенное |
| `docs/ARCHITECTURE.md` | Потоки данных, middle proxy, hot-reload |
| `docs/API.md` | REST API и WebUI |
| `docs/CONFIG.md` | YAML, env `PHANTOM_*`, ad_tag, middle proxy |
| `docs/DEPLOY.md` | systemd, install/uninstall, Prometheus |
| `CONTRIBUTING.md` | Workflow, PR checklist, CI |
| `configs/config.yaml` | Актуальный пример конфига |
| `.cursorrules` | Соглашения проекта |
| `.cursor/rules/*.mdc` | Контекст по областям (proxy, admin, go) |

## Ключевые компоненты

```
cmd/proxy/main.go           → CLI run/generate/uninstall/version
internal/proxy/server.go    → ee/dd routing, fronting, relay, middle proxy
internal/proxy/listen.go    → RebindListenIfNeeded (hot-reload port)
internal/faketls/           → TLS, replay, splice, DRS, Split-TLS
internal/middleproxy/       → ME handshake, adtag, RPC_PROXY_REQ/ANS
internal/user/manager.go    → multi-user, JA3/JA4, MatchSecure
internal/runtime/runtime.go → Reload, PersistUsers, Replay, Limiter
internal/service/           → systemd uninstall (API/UI/CLI)
internal/metrics/           → Prometheus endpoint
internal/upstream/          → SOCKS5 + IPv prefer (несовместим с ME)
internal/limit/             → max connections per IP
internal/admin/             → REST + WebUI, listen rebind on config change
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

### Hot-reload listen port

- `proxy.RebindListenIfNeeded()` — вызывается из admin после `Reload` / `UpdateSettings`
- API ответ: `listen_rebound`, `listen_addr`
- Тест: `internal/proxy/listen_test.go`

### Middle proxy / adtag

- Пакет `internal/middleproxy`
- Конфиг: `mtproto.ad_tag`, `use_middle_proxy`, `middle_proxy_nat_ip`
- При `ad_tag` ME включается автоматически
- SOCKS5 upstream отключает ME (fallback на direct)

### CRUD пользователей

- API: `internal/admin/server.go` → `rt.PersistUsers()` после изменений
- UI: `internal/admin/ui/handler.go` → то же

### WebUI шаблоны

- У каждой страницы свой блок: `dashboard_content`, `settings_content`, `users_content`
- Layout рендерит через `{{render .PageContent .}}` (не общий `content`)

## Ограничения

- Не добавляй Redis, БД, Celery
- Не меняй `go.mod` без необходимости; держи совместимость с Go 1.22
- Management API — только `127.0.0.1` в production
- Middle proxy требует публичный IPv4 для handshake (NAT → `middle_proxy_nat_ip`)
- Комментарии в коде — на русском

## Ветки и PR

- Формат: `cursor/<описание>-393e`
- Base: `main`
- CI: `GOTOOLCHAIN=local make ci` (+ fuzz в workflow)

## MCP (локально в Cursor)

`.cursor/mcp.json`:
- `filesystem` — файлы проекта
- `fetch` — HTTP к `:8081` (API/WebUI) и `:9090` (metrics)

## Проверка после изменений

```bash
GOTOOLCHAIN=local make ci
GOTOOLCHAIN=local make fuzz

curl -s http://127.0.0.1:8081/api/v1/health
curl -s -H "Authorization: Bearer change-me-in-production" \
  http://127.0.0.1:8081/api/v1/status
curl -s http://127.0.0.1:9090/metrics | head

./telegram-proxy generate www.google.com
```

E2E (opt-in, сеть):

```bash
PHANTOM_E2E_TELEGRAM=1 go test -tags=realtelegram -timeout=2m ./internal/proxy/...
```
