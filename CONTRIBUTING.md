# Руководство для контрибьюторов

Спасибо за интерес к PhantomProxy! Ниже — как настроить окружение, писать код и отправлять изменения.

## Перед началом

- Прочитай [README.md](README.md) и [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Для изменений конфигурации — [docs/CONFIG.md](docs/CONFIG.md)
- Для API/WebUI — [docs/API.md](docs/API.md)
- Для работы в Cursor — [AGENTS.md](AGENTS.md) и [.cursorrules](.cursorrules)

## Требования

- Go 1.22+
- `git`, `make`
- Docker + Docker Compose (опционально, для nginx-заглушки)

## Настройка окружения

```bash
git clone https://github.com/RioTwWks/PhantomProxy.git
cd PhantomProxy
go mod download
make build
```

Запуск с примерным конфигом:

```bash
# Терминал 1: заглушка (опционально)
docker compose up web

# Терминал 2: прокси
make run
```

- Прокси: `0.0.0.0:8443`
- WebUI: http://127.0.0.1:8081/ui/
- Токен по умолчанию: `change-me-in-production` (см. `configs/config.yaml`)

## Структура репозитория

```
cmd/proxy/           — точка входа
internal/            — вся бизнес-логика (приватные пакеты)
configs/             — пример config.yaml
docs/                — документация
web/                 — статика для nginx-заглушки
```

Публичного `pkg/` нет — проект не задуман как библиотека.

## Workflow разработки

1. Создай ветку от `main`:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b feature/my-change
   ```

2. Внеси изменения, следуя соглашениям ниже.

3. Прогони тесты:
   ```bash
   make test
   make integration   # если трогал proxy/faketls/obfuscated2
   ```

4. Закоммить с понятным сообщением (на русском или английском):
   ```bash
   git commit -m "feat: краткое описание изменения"
   ```

5. Открой Pull Request в `main` с описанием:
   - что изменилось и зачем
   - как проверить (test plan)

## Соглашения по коду

### Go

- Обрабатывай все ошибки: `fmt.Errorf("контекст: %w", err)`
- Не игнорируй ошибки через `_`
- Логирование: `log/slog`, не `fmt.Print` / `print`
- Сетевой I/O и shutdown — через `context.Context`
- Комментарии к неочевидной логике — **на русском**
- Следуй существующему стилю пакета, не рефактори попутно

### Архитектура

- `runtime.Runtime` — общее состояние proxy + admin
- Новые поля конфига: struct в `config.go` → defaults → `settings.go` (если в UI) → `docs/CONFIG.md`
- API-эндпоинты: handler в `admin/server.go` + тест + `docs/API.md`
- WebUI: шаблон в `admin/ui/templates/` + handler + тест

### Зависимости

- Не добавляй пакеты в `go.mod` без необходимости
- Запрещено без обсуждения: Redis, БД, Celery, тяжёлые фреймворки для UI

## Тестирование

| Команда | Назначение |
|---------|------------|
| `make test` | Unit-тесты, `-race` |
| `make integration` | E2E с mock DC (`-tags=integration`) |
| `make lint` | golangci-lint (если установлен) |
| `make fmt` | `go fmt ./...` |

### Где писать тесты

- Логика без сети → unit-тест рядом с кодом (`*_test.go`)
- Прокси end-to-end → `internal/proxy/integration_test.go`
- Mock DC → `internal/testdc/`
- Тестовый клиент → `internal/testclient/`

Интеграционные тесты **не требуют Docker** — mock DC in-process.

### Пример ручной проверки API

```bash
TOKEN="change-me-in-production"
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/api/v1/status | jq
```

## Документация

При изменении поведения обнови соответствующие файлы:

| Изменение | Документ |
|-----------|----------|
| Новое поле конфига | `docs/CONFIG.md`, `configs/config.yaml` |
| Новый API-эндпоинт | `docs/API.md` |
| Архитектурный сдвиг | `docs/ARCHITECTURE.md` |
| Пользовательские инструкции | `README.md` |

## Pull Request checklist

- [ ] `make test` проходит
- [ ] Интеграционные тесты прогнаны (если затронут data path)
- [ ] Документация обновлена
- [ ] Нет хардкода секретов и токенов
- [ ] Нет `print()` для логирования
- [ ] PR содержит test plan

## Сообщения коммитов

Предпочтительный формат:

```
<type>: <краткое описание>

feat: добавить эндпоинт /api/v1/metrics
fix: исправить выравнивание AES-CTR в mock DC
docs: обновить справочник env-переменных
test: покрыть RecordPolicy граничные случаи
```

## Вопросы и баги

- Баг: приложи шаги воспроизведения, версию Go, фрагмент конфига (без секретов), логи
- Фича: опиши use case и ожидаемое поведение

## Лицензия

Отправляя PR, ты соглашаешься, что код распространяется под [MIT](LICENSE).
