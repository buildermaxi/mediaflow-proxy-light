#!/usr/bin/env bash
# Install or update MediaFlow Proxy Light as a native systemd service, from the
# binaries attached to this repo's GitHub releases.
#
#   curl -fsSL https://github.com/buildermaxi/mediaflow-proxy-light/releases/latest/download/install.sh | sudo bash
#
# Re-run it to update; it only restarts the service when something changed.
#
# Optional environment variables:
#   MEDIAFLOW_VERSION       release tag to install instead of the latest one
#   MEDIAFLOW_API_PASSWORD  API password written on first install (default: random)
#
# Requires 64-bit Linux (x86_64 or arm64), systemd and glibc 2.36+ (Debian 12,
# Raspberry Pi OS Bookworm, Ubuntu 22.10 or newer).
set -euo pipefail

REPO=buildermaxi/mediaflow-proxy-light
NAME=mediaflow-proxy-light
BIN=/usr/local/bin/$NAME
UNIT=/etc/systemd/system/$NAME.service
CONF_DIR=/etc/$NAME
ENV_FILE=$CONF_DIR/env
# Oldest glibc the release binaries are guaranteed to run on (checked in CI).
MIN_GLIBC=2.36

if [[ -n ${MEDIAFLOW_VERSION:-} ]]; then
    BASE_URL=https://github.com/$REPO/releases/download/$MEDIAFLOW_VERSION
else
    BASE_URL=https://github.com/$REPO/releases/latest/download
fi

die() { echo "error: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root, e.g. with sudo"
command -v systemctl >/dev/null || die "systemd is required"
command -v curl >/dev/null || die "curl is required"

# The userland's word size, not the kernel's: 32-bit Raspberry Pi OS boots a
# 64-bit kernel on a Pi 4, so `uname -m` alone would say aarch64.
case "$(uname -m)-$(getconf LONG_BIT)" in
    x86_64-64) arch=amd64 ;;
    aarch64-64 | arm64-64) arch=arm64 ;;
    *) die "unsupported system ($(uname -m), $(getconf LONG_BIT)-bit userland). A 64-bit OS on x86_64 or arm64 is required; on a Raspberry Pi, install Raspberry Pi OS (64-bit)." ;;
esac

glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}') || true
[[ -n $glibc ]] || die "glibc is required (musl-based systems such as Alpine are not supported)"
printf '%s\n' "$MIN_GLIBC" "$glibc" | sort -V -C \
    || die "glibc $glibc is too old, $MIN_GLIBC+ is required (Debian 12 / Raspberry Pi OS Bookworm or newer)"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

asset=$NAME-linux-$arch
for file in SHA256SUMS "$asset" "$NAME.service"; do
    curl -fsSL --retry 3 -o "$tmp/$file" "$BASE_URL/$file" || die "could not download $BASE_URL/$file"
done

verify() {
    local want
    want=$(awk -v f="$1" '$2 == f || $2 == "*" f {print $1}' "$tmp/SHA256SUMS")
    [[ -n $want ]] || die "$1 is missing from SHA256SUMS"
    [[ $(sha256sum "$tmp/$1" | cut -d' ' -f1) == "$want" ]] || die "checksum mismatch for $1"
}
verify "$asset"
verify "$NAME.service"

changed=0
# Replace by rename, so a running process keeps its old binary until restarted.
install_file() { # <source> <destination> <mode>
    if ! cmp -s "$1" "$2"; then
        install -m "$3" "$1" "$2.new"
        mv -f "$2.new" "$2"
        changed=1
    fi
}
install_file "$tmp/$asset" "$BIN" 755
install_file "$tmp/$NAME.service" "$UNIT" 644

first_install=0
if [[ ! -f $ENV_FILE ]]; then
    first_install=1
    password=${MEDIAFLOW_API_PASSWORD:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}
    install -d -m 755 "$CONF_DIR"
    (
        umask 077
        cat >"$ENV_FILE" <<EOF
# MediaFlow Proxy Light configuration, see
# https://github.com/$REPO#configuration
# Apply changes with: sudo systemctl restart $NAME
APP__SERVER__HOST=0.0.0.0
APP__SERVER__PORT=8888
APP__AUTH__API_PASSWORD=$password
RUST_LOG=info
EOF
    )
fi

systemctl daemon-reload
systemctl enable --quiet "$NAME"
if [[ $changed -eq 1 ]] || ! systemctl is-active --quiet "$NAME"; then
    systemctl restart "$NAME"
fi

port=$(sed -n 's/^APP__SERVER__PORT=//p' "$ENV_FILE" | tail -n1)
port=${port:-8888}
healthy=0
for _ in $(seq 20); do
    if curl -fsS -o /dev/null "http://127.0.0.1:$port/health" 2>/dev/null; then
        healthy=1
        break
    fi
    sleep 0.5
done
if [[ $healthy -eq 0 ]]; then
    journalctl -u "$NAME" -n 20 --no-pager >&2 || true
    die "$NAME did not answer on port $port, see: journalctl -u $NAME"
fi

host=$(hostname -I 2>/dev/null | awk '{print $1}')
if [[ $first_install -eq 1 ]]; then
    echo "$NAME installed and running on http://${host:-<this-host>}:$port"
    if [[ -z ${MEDIAFLOW_API_PASSWORD:-} ]]; then
        echo "API password: $password"
    fi
    echo "Configuration: $ENV_FILE"
elif [[ $changed -eq 1 ]]; then
    echo "$NAME updated and restarted"
else
    echo "$NAME is already up to date"
fi
