#!/usr/bin/env bash
# Установка PhantomProxy как systemd-сервис (одна команда).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="${PHANTOM_SERVICE_NAME:-phantom-proxy}"
INSTALL_DIR="${PHANTOM_INSTALL_DIR:-/opt/phantomproxy}"
CONFIG_DIR="${PHANTOM_CONFIG_DIR:-/etc/phantomproxy}"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
SKIP_BUILD=0
FORCE_CONFIG=0
SOURCE_CONFIG="$ROOT/configs/config.yaml"

usage() {
  cat <<EOF
Использование: sudo bash deploy/install.sh [опции]

Опции:
  --no-build, --skip-build   не собирать бинарь (ожидается telegram-proxy в корне репо)
  --profile <default|ru|eu>  шаблон конфига (по умолчанию: default → configs/config.yaml)
  --config <path>            свой файл конфига вместо шаблона
  --force-config             перезаписать /etc/phantomproxy/config.yaml

Примеры:
  make install-service              # одиночный прокси (configs/config.yaml)
  make install-service-ru           # RU Front (configs/config.ru.yaml)
  make install-service-eu           # EU Back (configs/config.eu.yaml)
  sudo bash deploy/install.sh --no-build --profile ru --force-config
EOF
}

resolve_profile() {
  case "$1" in
    default) SOURCE_CONFIG="$ROOT/configs/config.yaml" ;;
    ru) SOURCE_CONFIG="$ROOT/configs/config.ru.yaml" ;;
    eu) SOURCE_CONFIG="$ROOT/configs/config.eu.yaml" ;;
    *)
      echo "Неизвестный профиль: $1 (допустимо: default, ru, eu)" >&2
      exit 1
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build|--skip-build) SKIP_BUILD=1 ;;
    --force-config) FORCE_CONFIG=1 ;;
    --profile)
      shift
      [[ $# -gt 0 ]] || { echo "Ожидается аргумент после --profile" >&2; exit 1; }
      resolve_profile "$1"
      ;;
    --config)
      shift
      [[ $# -gt 0 ]] || { echo "Ожидается путь после --config" >&2; exit 1; }
      SOURCE_CONFIG="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Неизвестный аргумент: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done
[[ "${PHANTOM_SKIP_BUILD:-}" == "1" ]] && SKIP_BUILD=1

if [[ "${EUID:-0}" -ne 0 ]]; then
  echo "Запусти: sudo bash $0" >&2
  exit 1
fi

if [[ ! -f "$SOURCE_CONFIG" ]]; then
  echo "Файл конфигурации не найден: $SOURCE_CONFIG" >&2
  exit 1
fi

build_proxy() {
  export GOTOOLCHAIN=local
  if command -v go &>/dev/null; then
    make -C "$ROOT" build
    return
  fi
  if [[ -n "${SUDO_USER:-}" ]] && sudo -u "$SUDO_USER" -H bash -lc 'command -v go >/dev/null'; then
    sudo -u "$SUDO_USER" -H bash -lc "cd '$ROOT' && export GOTOOLCHAIN=local && make build"
    return
  fi
  echo "Go не найден в PATH root. Собери от своего пользователя: make build" >&2
  echo "Затем: sudo bash deploy/install.sh --no-build" >&2
  exit 1
}

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "==> Сборка"
  build_proxy
elif [[ ! -x "$ROOT/telegram-proxy" ]]; then
  echo "Бинарь $ROOT/telegram-proxy не найден. Запусти: make build" >&2
  exit 1
fi

echo "==> Пользователь phantom"
id phantom &>/dev/null || useradd -r -s /usr/sbin/nologin phantom

echo "==> Установка файлов"
install -d -m 755 "$INSTALL_DIR"
install -d -m 750 "$CONFIG_DIR"
install -m 755 "$ROOT/telegram-proxy" "$INSTALL_DIR/"
if [[ ! -f "$CONFIG_DIR/config.yaml" ]] || [[ "$FORCE_CONFIG" -eq 1 ]]; then
  if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
    echo "==> Перезапись конфигурации из $SOURCE_CONFIG"
  else
    echo "==> Конфигурация из $SOURCE_CONFIG"
  fi
  install -m 600 "$SOURCE_CONFIG" "$CONFIG_DIR/config.yaml"
elif [[ -f "$CONFIG_DIR/config.yaml" ]]; then
  echo "==> Конфиг уже есть: $CONFIG_DIR/config.yaml (не перезаписываем; --force-config чтобы заменить)" >&2
fi
install -m 755 "$ROOT/deploy/uninstall.sh" "$INSTALL_DIR/uninstall.sh"
install -m 755 "$ROOT/deploy/diagnose.sh" "$INSTALL_DIR/diagnose.sh"

# Сервис работает от пользователя phantom — ему нужны чтение и запись конфига (PersistUsers).
chown -R phantom:phantom "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
chmod 600 "$CONFIG_DIR/config.yaml"

echo "==> Проверка конфигурации"
if ! sudo -u phantom "$INSTALL_DIR/telegram-proxy" check -config "$CONFIG_DIR/config.yaml"; then
  echo "" >&2
  echo "ВНИМАНИЕ: конфигурация невалидна — сервис не запустится." >&2
  if grep -qE 'REPLACE_WITH|EU_SERVER_IP|RU_SERVER_IP|CHANGE-ME|EU_PUBLIC_IPV4' "$CONFIG_DIR/config.yaml" 2>/dev/null; then
    echo "В конфиге остались placeholder-значения из configs/config.ru.yaml." >&2
    echo "Сгенерируй секрет: ./telegram-proxy generate microsoft.com" >&2
    echo "Затем отредактируй $CONFIG_DIR/config.yaml (docs/RELAY.md)." >&2
  fi
  echo "Диагностика: sudo bash $INSTALL_DIR/diagnose.sh" >&2
  echo "" >&2
fi

echo "==> systemd unit"
sed "s|/opt/phantomproxy|$INSTALL_DIR|g; s|/etc/phantomproxy|$CONFIG_DIR|g; s|phantom-proxy|$SERVICE_NAME|g" \
  "$ROOT/deploy/phantom-proxy.service" > "$UNIT_PATH"

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

echo ""
echo "Готово. Проверка:"
echo "  systemctl status $SERVICE_NAME"
echo "  curl -s http://127.0.0.1:8081/api/v1/health"
echo ""
echo "Удаление одной командой:"
echo "  sudo bash $INSTALL_DIR/uninstall.sh"
echo ""
echo "Диагностика при сбое:"
echo "  sudo bash $INSTALL_DIR/diagnose.sh"
