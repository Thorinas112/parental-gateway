#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Parental Gateway - host preparation
#
# Fixes the three things that most often break a fresh Docker install on
# Ubuntu/Debian before deploying the gateway:
#
#   1. the Compose V2 plugin  (Ubuntu's docker.io package does not ship it)
#   2. the buildx plugin      (otherwise builds use the deprecated legacy builder)
#   3. docker group membership (otherwise every command needs sudo)
#
# Then optionally clones, configures and starts the gateway.
#
#   curl -fsSL https://raw.githubusercontent.com/Thorinas112/parental-gateway/main/scripts/setup-host.sh | bash
#
#   ...or, to also clone and deploy in one go:
#
#   curl -fsSL .../setup-host.sh | bash -s -- --deploy
#
# This script is deliberately explicit: it prints every command it runs and
# never removes anything.
# ---------------------------------------------------------------------------
set -euo pipefail

DEPLOY=0
REPO_URL="${REPO_URL:-https://github.com/Thorinas112/parental-gateway.git}"
TARGET_DIR="${TARGET_DIR:-$HOME/parental-gateway}"

for arg in "$@"; do
    case "$arg" in
        --deploy) DEPLOY=1 ;;
        -h|--help)
            sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 1 ;;
    esac
done

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32mok\033[0m   %s\n' "$*"; }
warn() { printf '    \033[1;33m!\033[0m    %s\n' "$*"; }
die()  { printf '    \033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        SUDO="sudo"
    elif command -v sudo >/dev/null 2>&1; then
        log "sudo is required to install packages and change group membership"
        sudo -v || die "cannot obtain sudo privileges"
        SUDO="sudo"
    else
        die "run this script as root, or install sudo"
    fi
fi

# --------------------------------------------------------------------------
log "Checking Docker"
if ! command -v docker >/dev/null 2>&1; then
    die "docker is not installed. On Ubuntu: sudo apt-get install -y docker.io"
fi
ok "$(docker --version)"

if docker info >/dev/null 2>&1; then
    ok "docker socket reachable as $(id -un)"
else
    warn "docker socket needs elevated privileges"
    NEED_DOCKER_GROUP=1
fi

# --------------------------------------------------------------------------
log "Checking the Compose V2 plugin"
if docker compose version >/dev/null 2>&1; then
    ok "$(docker compose version --short 2>/dev/null || echo 'compose plugin present')"
else
    warn "docker compose is missing"
    if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
        log "Installing docker-compose-v2 from apt"
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq docker-compose-v2
    else
        log "docker-compose-v2 not in apt - installing the release binary"
        DEST_DIR="$HOME/.docker/cli-plugins"
        mkdir -p "$DEST_DIR"
        ARCH="$(uname -m)"
        case "$ARCH" in
            x86_64)  ARCH=linux-x86_64 ;;
            aarch64) ARCH=linux-aarch64 ;;
            armv7l)  ARCH=linux-armv7 ;;
            *) die "unsupported architecture: $ARCH" ;;
        esac
        curl -fsSL -o "$DEST_DIR/docker-compose" \
            "https://github.com/docker/compose/releases/latest/download/docker-compose-${ARCH}"
        chmod +x "$DEST_DIR/docker-compose"
    fi
    docker compose version >/dev/null 2>&1 && ok "compose plugin installed" \
        || die "compose plugin still unavailable"
fi

# --------------------------------------------------------------------------
log "Checking the buildx plugin"
if docker buildx version >/dev/null 2>&1; then
    ok "$(docker buildx version 2>/dev/null | head -1)"
else
    warn "buildx is missing - builds would use the deprecated legacy builder"
    if apt-cache show docker-buildx >/dev/null 2>&1; then
        $SUDO apt-get install -y -qq docker-buildx
        ok "buildx installed"
    else
        warn "could not install buildx from apt; continuing with the legacy builder"
    fi
fi

# --------------------------------------------------------------------------
if [ "${NEED_DOCKER_GROUP:-0}" = "1" ]; then
    log "Adding $(id -un) to the docker group"
    $SUDO usermod -aG docker "$(id -un)"
    ok "added - you must log out and back in (or run 'newgrp docker') for it to apply"
    warn "the rest of this script will use sudo for docker commands"
    DOCKER="sudo docker"
else
    DOCKER="docker"
fi

# --------------------------------------------------------------------------
if [ "$DEPLOY" = "0" ]; then
    log "Host is ready."
    echo
    echo "  Next: clone and deploy"
    echo "    git clone $REPO_URL $TARGET_DIR"
    echo "    cd $TARGET_DIR && cp .env.example .env && nano .env"
    echo "    docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build"
    echo
    echo "  Or re-run this script with --deploy to do all of that automatically."
    exit 0
fi

# --------------------------------------------------------------------------
log "Cloning into $TARGET_DIR"
if [ -d "$TARGET_DIR/.git" ]; then
    ok "already cloned"
else
    git clone "$REPO_URL" "$TARGET_DIR"
fi
cd "$TARGET_DIR"

if [ ! -f .env ]; then
    cp .env.example .env
    ok "created .env from .env.example"
    warn "edit .env now - set LAN_IFACE, WAN_IFACE and ADMIN_PASSWORD"
    echo
    echo "    nano $TARGET_DIR/.env"
    echo
    echo "  Re-run this script with --deploy once you have."
    exit 0
fi

log "Building and starting"
mkdir -p data
$DOCKER compose -f docker-compose.yml -f docker-compose.build.yml up -d --build

echo
log "Done. Current status:"
$DOCKER compose -f docker-compose.yml -f docker-compose.build.yml ps
echo
echo "  Open:  http://$(hostname -I 2>/dev/null | awk '{print $1}'):$(grep -E '^WEB_PORT=' .env | cut -d= -f2)"
echo "  Logs:  $DOCKER compose logs -f"
