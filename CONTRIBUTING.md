# Руководство для контрибьюторов

Спасибо за интерес к PhantomProxy! Ниже — как настроить окружение, писать код и отправлять изменения.

## Перед началом

| Документ | Когда читать |
|----------|--------------|
| [README.md](README.md) | Обзор проекта |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Потоки данных, пакеты |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Что реализовано и что в v2 |
| [docs/CONFIG.md](docs/CONFIG.md) | YAML и env `PHANTOM_*` |
| [docs/API.md](docs/API.md) | REST API и WebUI |
| [docs/DEPLOY.md](docs/DEPLOY.md) | systemd, nginx, Prometheus |
| [AGENTS.md](AGENTS.md), [.cursorrules](.cursorrules) | Работа в Cursor |

## Требования

- Go **1.22+** (в `PATH`, без автозагрузки toolchain)
- `git`, `make`
- Docker + Docker Compose (опционально, для nginx-заглушки)
- `jq` (опционально, для проверки API)

### Go toolchain

Проект закреплён на Go 1.22. Чтобы `go` не пытался скачать более новый toolchain из `go.mod`, **всегда** используй:

```bash
export GOTOOLCHAIN=local
```

`make test`, `make integration` и `make build` уже выставляют эту переменную. В CI — то же самое (см. ниже).

## Настройка окружения

```bash
git clone https://github.com/RioTwWks/PhantomProxy.git
cd PhantomProxy
export GOTOOLCHAIN=local
go mod download
make build
```

### Запуск

```bash
# Терминал 1: заглушка (опционально)
docker compose up web

# Терминал 2: прокси
make run
# или явно:
./telegram-proxy run -config configs/config.yaml
```

| Сервис | URL |
|--------|-----|
| Прокси | `0.0.0.0:8443` |
| WebUI | http://127.0.0.1:8081/ui/ |
| REST API | http://127.0.0.1:8081/api/v1/ |
| Prometheus | http://127.0.0.1:9090/metrics |

Токен по умолчанию: `change-me-in-production` (см. `configs/config.yaml`).

### CLI

```bash
./telegram-proxy run -config configs/config.yaml
./telegram-proxy generate www.google.com    # ee + dd секреты
./telegram-proxy version
./telegram-proxy -config path               # legacy-форма запуска
```

## Структура репозитория

```
cmd/proxy/              — CLI и точка входа
configs/                — пример config.yaml
deploy/                 — systemd unit
internal/
  admin/                — REST API + WebUI
  config/               — Load, Save, SettingsView
  faketls/              — Fake TLS, replay, fronting, DRS
  fallback/             — HTTP upstream
  limit/                — лимит соединений per-IP
  metrics/              — Prometheus
  mtproto/              — секреты ee/dd
  obfuscated2/          — handshake
  proxy/                — TCP server, PROXY protocol
  runtime/              — Reload, PersistUsers
  stats/                — in-memory счётчики
  telegram/             — DC resolver
  upstream/             — SOCKS5 dialer
  testclient/           — тестовый клиент
  testdc/               — mock DC
  user/                 — multi-user manager
docs/                   — документация
.github/workflows/      — CI (GitHub Actions)
web/                    — статика nginx-заглушки
```

Публичного `pkg/` нет — проект не задуман как библиотека.

## Workflow разработки

1. Создай ветку от `main`:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b cursor/my-feature-393e
   ```

2. Внеси изменения, следуя соглашениям ниже.

3. Прогони тесты локально (как в CI):
   ```bash
   export GOTOOLCHAIN=local
   make test
   make integration   # обязательно при изменениях proxy/faketls/obfuscated2
   make build
   ```

4. Закоммить с понятным сообщением:
   ```bash
   git commit -m "feat: краткое описание изменения"
   ```

5. Открой Pull Request в `main`:
   - что изменилось и зачем
   - test plan (команды для проверки)

## CI (GitHub Actions)

На каждый push/PR в `main` запускается [`.github/workflows/ci.yml`](.github/workflows/ci.yml):

1. Unit-тесты: `GOTOOLCHAIN=local go test -race ./...`
2. Интеграционные: `GOTOOLCHAIN=local go test -race -tags=integration ./internal/proxy/...`
3. Сборка: `GOTOOLCHAIN=local go build -o telegram-proxy ./cmd/proxy`

PR не должен ломать CI. Локально воспроизведи те же команды перед пушем.

## Соглашения по коду

### Go

- Обрабатывай все ошибки: `fmt.Errorf("контекст: %w", err)`
- Не игнорируй ошибки через `_`
- Логирование: `log/slog`, не `print` / `fmt.Print`
- Сетевой I/O и shutdown — через `context.Context`
- Комментарии к неочевидной логике — **на русском**

### Архитектура

- `runtime.Runtime` — общее состояние (Config, Users, Stats, Replay, Limiter)
- **Users CRUD** (API/UI) → всегда вызывай `runtime.PersistUsers()` после изменений
- Новое поле конфига: `config.go` → defaults → `settings.go` (если в UI) → `docs/CONFIG.md` → `configs/config.yaml`
- API: `admin/server.go` + тест + `docs/API.md`
- WebUI: шаблон + handler + тест; HTMX — локально в `static/htmx.min.js`

### Зависимости

- Не добавляй пакеты в `go.mod` без необходимости; сохраняй совместимость с **Go 1.22**
- Запрещено без обсуждения: Redis, БД, Celery, тяжёлые UI-фреймворки

## Тестирование

| Команда | Назначение |
|---------|------------|
| `make test` | Unit-тесты, `-race` (`GOTOOLCHAIN=local`) |
| `make integration` | E2E с mock DC (`-tags=integration`) |
| `make build` | Сборка `telegram-proxy` |
| `make fmt` | `go fmt ./...` |
| `make lint` | golangci-lint (если установлен) |
| `make clean` | Удаление бинарника и test cache |

Эквивалент без Make:

```bash
export GOTOOLCHAIN=local
go test -race ./...
go test -race -tags=integration ./internal/proxy/...
go build -o telegram-proxy ./cmd/proxy
```

### Где писать тесты

| Область | Файл |
|---------|------|
| Unit-логика | `*_test.go` рядом с кодом |
| Прокси E2E | `internal/proxy/integration_test.go` |
| Mock DC | `internal/testdc/` |
| Тестовый клиент | `internal/testclient/` |

Интеграционные тесты **не требуют Docker** — mock DC in-process.

При изменении отклонённого Fake TLS учитывай `fronting.action` в тестах (`splice` / `redirect` / `fallback`).

### Ручная проверка

```bash
TOKEN="change-me-in-production"

# API
curl -s http://127.0.0.1:8081/api/v1/health
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/api/v1/status | jq

# Prometheus
curl -s http://127.0.0.1:9090/metrics | head -20

# Генерация секретов
./telegram-proxy generate storage.googleapis.com
```

## Документация

| Изменение | Обновить |
|-----------|----------|
| Поле конфига | `docs/CONFIG.md`, `configs/config.yaml` |
| API-эндпоинт | `docs/API.md` |
| Поток данных / пакеты | `docs/ARCHITECTURE.md` |
| Деплой / метрики | `docs/DEPLOY.md` |
| Новая фича / план | `docs/ROADMAP.md` |
| Пользовательский обзор | `README.md` |
| Cursor / агенты | `AGENTS.md`, `.cursorrules` |

## Pull Request checklist

- [ ] `GOTOOLCHAIN=local make test` проходит
- [ ] `GOTOOLCHAIN=local make integration` прогнан (если затронут data path)
- [ ] `make build` успешен
- [ ] Документация обновлена
- [ ] Users CRUD вызывает `PersistUsers()` (если менял admin/UI)
- [ ] Нет хардкода секретов и токенов
- [ ] Нет `print()` для логирования
- [ ] PR содержит test plan

## Сообщения коммитов

```
feat: добавить метрику phantom_fronting_connections_total
fix: исправить splice при частичном ClientHello
docs: синхронизировать CONTRIBUTING с GOTOOLCHAIN=local
test: покрыть MatchSecureHeader для dd
```

## Вопросы и баги

- **Баг:** шаги воспроизведения, `go version`, фрагмент конфига (без секретов), логи
- **Фича:** use case и ожидаемое поведение; сверься с `docs/ROADMAP.md` (v2)

## Лицензия

Отправляя PR, ты соглашаешься, что код распространяется под [MIT](LICENSE).
