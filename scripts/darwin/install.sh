#!/bin/sh
# VPN Guard installer for macOS.
#
#   sudo ./install.sh [--binary PATH] [--config PATH] [--force-config]
#
# Defaults: binary ./vpn-guard (or bin/darwin/vpn-guard from a source tree),
# config ./config.json, else config.example.json. An existing
# /etc/vpn-guard/config.json is kept unless --force-config is given.
set -eu

LABEL="com.vpnguard.daemon"
BIN_DST="/usr/local/bin/vpn-guard"
CFG_DIR="/etc/vpn-guard"
CFG_DST="$CFG_DIR/config.json"
PLIST_DST="/Library/LaunchDaemons/$LABEL.plist"
LOG="/var/log/vpn-guard.log"
ERRLOG="/var/log/vpn-guard-error.log"

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." 2>/dev/null && pwd || echo "$HERE")

BINARY=""
CONFIG=""
FORCE_CONFIG=0
while [ $# -gt 0 ]; do
	case "$1" in
	--binary) BINARY="$2"; shift 2 ;;
	--config) CONFIG="$2"; shift 2 ;;
	--force-config) FORCE_CONFIG=1; shift ;;
	-h|--help) sed -n '2,9p' "$0"; exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

die() { echo "error: $*" >&2; exit 1; }
first() { for f in "$@"; do [ -f "$f" ] && { echo "$f"; return 0; }; done; return 1; }

# 1. macOS
[ "$(uname -s)" = "Darwin" ] || die "this installer is for macOS"
# 2. root
[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"

[ -n "$BINARY" ] || BINARY=$(first "$HERE/vpn-guard" "$ROOT/bin/darwin/vpn-guard") || die "binary not found; build with 'make darwin' or pass --binary"
[ -n "$CONFIG" ] || CONFIG=$(first "$HERE/config.json" "$ROOT/config.json" "$HERE/config.example.json" "$ROOT/config.example.json") || true
PLIST_SRC=$(first "$HERE/$LABEL.plist" "$ROOT/deploy/darwin/$LABEL.plist") || die "$LABEL.plist not found"

# Stop a running instance before replacing the binary.
launchctl bootout "system/$LABEL" 2>/dev/null || true

# 3. binary
mkdir -p /usr/local/bin
install -o root -g wheel -m 0755 "$BINARY" "$BIN_DST"
xattr -d com.apple.quarantine "$BIN_DST" 2>/dev/null || true

# 4. config directory, 5. config
install -d -o root -g wheel -m 0755 "$CFG_DIR"
if [ ! -f "$CFG_DST" ] || [ "$FORCE_CONFIG" -eq 1 ]; then
	[ -n "$CONFIG" ] || die "no config to install; pass --config"
	install -o root -g wheel -m 0600 "$CONFIG" "$CFG_DST"
	echo "installed config: $CFG_DST"
else
	echo "keeping existing config: $CFG_DST"
fi

# 6. LaunchDaemon
install -o root -g wheel -m 0644 "$PLIST_SRC" "$PLIST_DST"

# 7. permissions (config holds the GeoIP token: root-only)
chown root:wheel "$BIN_DST" "$CFG_DIR" "$CFG_DST" "$PLIST_DST"
chmod 0755 "$BIN_DST" "$CFG_DIR"
chmod 0600 "$CFG_DST"
chmod 0644 "$PLIST_DST"
touch "$LOG" "$ERRLOG"
chown root:wheel "$LOG" "$ERRLOG"
chmod 0644 "$LOG" "$ERRLOG"

if ! "$BIN_DST" validate -config "$CFG_DST"; then
	echo "warning: configuration is invalid; the daemon will run fail-closed (application blocked) until it is fixed" >&2
fi

# 8. register, 9. start
launchctl bootstrap system "$PLIST_DST"
launchctl enable "system/$LABEL"
launchctl kickstart -k "system/$LABEL"

# 10. verify
sleep 2
if launchctl print "system/$LABEL" 2>/dev/null | grep -q "state = running"; then
	echo "vpn-guard is running"
else
	launchctl print "system/$LABEL" 2>&1 | head -30 >&2 || true
	die "vpn-guard did not start; see $ERRLOG"
fi
"$BIN_DST" status || true
