# Roadmap PhantomProxy

План развития по сравнению с mtg, telego, telemt.

## Phase 1 — Маскировка и протоколы ✅

| Задача | Статус |
|--------|--------|
| TCP domain fronting (splice на mask host) | ✅ |
| Anti-replay cache | ✅ |
| Протокол `dd` (secure obfuscated2) | ✅ |
| DRS + Split-TLS для исходящих записей | ✅ |
| Whitelist JA4 | ✅ |

## Phase 2 — Production ✅

| Задача | Статус |
|--------|--------|
| Prometheus `/metrics` | ✅ |
| GitHub Actions CI | ✅ |
| Автосохранение users при CRUD | ✅ |
| Исправление docker-compose | ✅ |
| systemd unit + docs/DEPLOY.md | ✅ |

## Phase 3 — Hardening ✅

| Задача | Статус |
|--------|--------|
| Лимит соединений per-IP | ✅ |
| Handshake timeout (конфигурируемый) | ✅ |
| SOCKS5 upstream для DC | ✅ |
| PROXY protocol v1 на listener | ✅ |
| IPv4/IPv6 preference для DC | ✅ |

## Phase 4 — UX и CLI ✅

| Задача | Статус |
|--------|--------|
| CLI: `run`, `generate`, `version` | ✅ |
| HTMX встроен (без CDN) | ✅ |
| Улучшенные cookie WebUI (HttpOnly, SameSite) | ✅ |

## Отложено (v2)

| Задача | Причина |
|--------|---------|
| Hot-reload listen port | Требует rebind listener |
| E2E против реального Telegram | Flaky CI, нужен network |
| Adtag / middle proxy | Сложность, низкая ценность |
| Telegram-бот | Обёртка над API, отдельный проект |
| Per-user byte quotas | Нужна персистентная БД |
| Real LE cert fetch | Требует nginx sidecar |
| Fuzz в CI | Отдельный PR |
