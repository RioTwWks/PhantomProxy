#!/usr/bin/env bash
# Диагностика phantom-proxy после установки (запускать на проблемном сервере).
set -euo pipefail

INSTALL_DIR="${PHANTOM_INSTALL_DIR:-/opt/phantomproxy}"
CONFIG_DIR="${PHANTOM_CONFIG_DIR:-/etc/phantomproxy}"
CONFIG="${PHANTOM_CONFIG:-$CONFIG_DIR/config.yaml}"
SERVICE_NAME="${PHANTOM_SERVICE_NAME:-phantom-proxy}"
BINARY="$INSTALL_DIR/telegram-proxy"

need_root() {
  if [[ "${EUID:-0}" -ne 0 ]]; then
    echo "Запусти: sudo bash $0" >&2
    exit 1
  fi
}

need_root

echo "=== PhantomProxy diagnose ==="
echo "config: $CONFIG"
echo "binary: $BINARY"
echo ""

fail=0

if [[ ! -x "$BINARY" ]]; then
  echo "FAIL: бинарь $BINARY не найден или не исполняемый"
  fail=1
else
  echo "OK: бинарь найден ($("$BINARY" version 2>/dev/null || echo '?'))"
fi

echo ""
echo "=== Права на конфиг ==="
if id phantom &>/dev/null; then
  if sudo -u phantom test -r "$CONFIG" 2>/dev/null; then
    echo "OK: пользователь phantom читает $CONFIG"
  else
    echo "FAIL: phantom не может прочитать $CONFIG"
    ls -la "$CONFIG_DIR/" 2>/dev/null || true
    echo "  исправление: sudo chown -R phantom:phantom $CONFIG_DIR && sudo chmod 750 $CONFIG_DIR && sudo chmod 600 $CONFIG"
    fail=1
  fi
else
  echo "WARN: пользователь phantom не существует"
fi

if [[ -f "$CONFIG" ]] && grep -qE 'REPLACE_WITH|EU_SERVER_IP|RU_SERVER_IP|CHANGE-ME|EU_PUBLIC_IPV4' "$CONFIG"; then
  echo "FAIL: в конфиге остались placeholder-значения (REPLACE_WITH, EU_SERVER_IP, …)"
  echo "  для RU Front: ./telegram-proxy generate microsoft.com"
  echo "  затем отредактируй $CONFIG (см. configs/config.ru.yaml, docs/RELAY.md)"
  fail=1
fi

echo ""
echo "=== Валидация конфигурации ==="
if [[ -x "$BINARY" ]] && id phantom &>/dev/null; then
  if sudo -u phantom "$BINARY" check -config "$CONFIG" 2>&1; then
    :
  else
    echo "FAIL: telegram-proxy check — см. сообщение выше"
    fail=1
  fi
else
  echo "SKIP: нет бинаря или пользователя phantom"
fi

echo ""
echo "=== Занятые порты ==="
check_port() {
  local port="$1"
  local label="$2"
  if command -v ss &>/dev/null; then
    if ss -tln 2>/dev/null | grep -q ":${port} "; then
      echo "BUSY: $label порт $port — $(ss -tlnp 2>/dev/null | grep ":${port} " | head -1 || echo '?')"
      return 1
    fi
  fi
  echo "FREE: $label порт $port"
  return 0
}

if [[ -f "$CONFIG" ]]; then
  listen_port=$(grep -A5 '^listen:' "$CONFIG" | grep 'port:' | head -1 | awk '{print $2}' | tr -d '"' || true)
  relay_port=$(grep -A5 '^relay:' "$CONFIG" | grep 'listen_port:' | head -1 | awk '{print $2}' | tr -d '"' || true)
  mgmt_port=$(grep -A5 '^management:' "$CONFIG" | grep 'port:' | head -1 | awk '{print $2}' | tr -d '"' || true)
  metrics_port=$(grep -A5 '^metrics:' "$CONFIG" | grep 'port:' | head -1 | awk '{print $2}' | tr -d '"' || true)

  [[ -n "${listen_port:-}" ]] && check_port "$listen_port" "listen" || fail=1
  [[ -n "${relay_port:-}" ]] && check_port "$relay_port" "relay" || fail=1
  [[ -n "${mgmt_port:-}" ]] && check_port "${mgmt_port:-8081}" "management" || fail=1
  [[ -n "${metrics_port:-}" && "${metrics_port:-0}" != "0" ]] && check_port "${metrics_port:-9090}" "metrics" || fail=1
fi

echo ""
echo "=== Логи systemd ($SERVICE_NAME) ==="
if command -v journalctl &>/dev/null; then
  journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null || echo "(нет записей)"
else
  echo "journalctl недоступен"
fi

echo ""
echo "=== Smoke test (2 сек от phantom) ==="
if [[ -x "$BINARY" ]] && id phantom &>/dev/null && sudo -u phantom test -r "$CONFIG" 2>/dev/null; then
  set +e
  timeout 2 sudo -u phantom "$BINARY" run -config "$CONFIG" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 124 ]]; then
    echo "OK: процесс стартовал (остановлен по timeout)"
  else
    echo "FAIL: процесс завершился с кодом $rc (см. вывод выше)"
    fail=1
  fi
else
  echo "SKIP"
fi

echo ""
if [[ "$fail" -eq 0 ]]; then
  echo "Итог: проблем не найдено. Попробуй: sudo systemctl restart $SERVICE_NAME"
else
  echo "Итог: найдены проблемы — исправь и перезапусти: sudo systemctl restart $SERVICE_NAME"
  exit 1
fi
