# Архитектура PhantomProxy

## Обзор

PhantomProxy — это TCP-прокси без терминации TLS на уровне `crypto/tls`. Вместо этого клиент Telegram отправляет **Fake TLS** ClientHello, а прокси:

1. Распознаёт MTProto-секрет внутри ClientHello
2. Отвечает синтетическим ServerHello (с padding/noise)
3. Устанавливает obfuscated2-сессию и ретранслирует трафик в Telegram DC

Посторонние клиенты (браузеры, сканеры) получают HTTP-проксирование на `fallback.upstream`.

## Поток соединения MTProto

```mermaid
sequenceDiagram
    participant C as Telegram клиент
    participant P as PhantomProxy
    participant DC as Telegram DC

    C->>P: TCP connect
    C->>P: Fake TLS ClientHello (секрет внутри)
    P->>P: Парсинг ClientHello, JA3/JA4
    P->>P: Сопоставление секрета с user.Manager
    alt валидный секрет
        P->>C: Fake TLS ServerHello + noise
        C->>P: obfuscated2 handshake
        P->>DC: TCP connect
        P->>DC: obfuscated2 relay
        loop данные
            C->>P: TLS Application Data (обфусцировано)
            P->>DC: расшифрованный MTProto
            DC->>P: ответ
            P->>C: TLS Application Data (динамический chunk)
        end
    else нет секрета
        P->>C: HTTP fallback (прокси на upstream)
    end
```

## Пакеты

### `internal/proxy`

TCP-акцептор. На каждое соединение — отдельная горутина. Читает первый пакет, вызывает детектор, маршрутизирует в MTProto relay или fallback.

### `internal/faketls`

- Парсинг ClientHello (SNI, cipher suites, extensions)
- Вычисление JA3/JA4 отпечатков
- Генерация ServerHello с `utls`
- `RecordPolicy` — случайная нарезка Application Data на TLS-записи
- `NoiseParams` — padding в ServerHello

### `internal/user`

Thread-safe менеджер пользователей (`sync.RWMutex`):

- Сопоставление входящего ClientHello с секретом
- CRUD через API
- Опциональный белый список JA3 (`tls.allowed_ja3`)
- Генерация секретов с кастомным SNI-доменом

### `internal/obfuscated2`

Реализация obfuscated2 handshake поверх Fake TLS:

- Извлечение ключа из ClientHello
- AES-CTR шифрование потока после рукопожатия

### `internal/mtproto`

Парсинг и кодирование hex-секретов MTProto (`ee` + random + domain).

### `internal/telegram`

Резолв адреса Telegram DC. Если `mtproto.backend` пуст, используется встроенный список DC.

### `internal/fallback`

HTTP reverse proxy для не-MTProto соединений. Проксирует на `fallback.upstream` (обычно nginx с `web/index.html`).

### `internal/runtime`

Общее состояние между прокси и admin API:

- `Snapshot()` / `UpdateConfig()` — thread-safe доступ к конфигу
- `Reload()` — перечитывание YAML
- `UpdateSettings()` — изменение настроек + запись на диск

### `internal/stats`

Счётчики соединений и трафика (общие и per-user).

### `internal/admin`

HTTP-сервер управления:

- REST API (`/api/v1/*`)
- WebUI (`/ui/*`) — `go:embed` шаблоны и статика

### `internal/config`

Загрузка через Viper (YAML + `PHANTOM_*` env). Сохранение через `gopkg.in/yaml.v3`.

## Тестовая инфраструктура

| Пакет | Назначение |
|-------|------------|
| `internal/testclient` | Эмуляция Telegram-клиента (Fake TLS + obfuscated2) |
| `internal/testdc` | Mock Telegram DC с AES-CTR |
| `internal/proxy/integration_test.go` | End-to-end тест прокси ↔ mock DC |

Интеграционные тесты: `go test -tags=integration ./internal/proxy/...`

## Конкурентность

- Каждое TCP-соединение — отдельная горутина в `proxy.Server`
- `runtime.Runtime` и `user.Manager` защищены `RWMutex`
- `stats.Tracker` — атомарные счётчики
- Graceful shutdown: `signal.NotifyContext` → закрытие listener → `WaitGroup` на активные соединения

## Безопасность

- Management API по умолчанию слушает только `127.0.0.1`
- Обязательно смени `management.token` в production
- Конфиг с секретами записывается с правами `0600`
- WebUI-сессия = значение токена в cookie (без JWT)

## Ограничения

- Изменение `listen.port` через API/UI применяется без перезапуска (hot-reload)
- Нет встроенного TLS-терминатора для management (используй reverse proxy)
- Один инстанс = один конфиг-файл (без кластеризации)
