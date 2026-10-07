#!/bin/sh
# VPN Guard installer for macOS.
#
#   sudo ./install.sh [--binary PATH] [--app PATH] [--config PATH] [--force-config] [--no-agent]
#
# Installs the root daemon and the "VPN Guard" menu bar app (settings UI).
# Defaults: ./vpn-guard and "./VPN Guard.app" (or bin/darwin/ from a source
# tree), config ./config.json, else config.example.json. An existing
# /etc/vpn-guard/config.json is kept unless --force-config is given.
set -eu

LABEL="com.vpnguard.daemon"
BIN_DST="/usr/local/bin/vpn-guard"
CFG_DIR="/etc/vpn-guard"
CFG_DST="$CFG_DIR/config.json"
PLIST_DST="/Library/LaunchDaemons/$LABEL.plist"
AGENT_LABEL="com.vpnguard.agent"
AGENT_PLIST_DST="/Library/LaunchAgents/$AGENT_LABEL.plist"
APP_DST="/Applications/VPN Guard.app"
LOG="/var/log/vpn-guard.log"
ERRLOG="/var/log/vpn-guard-error.log"

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." 2>/dev/null && pwd || echo "$HERE")

BINARY=""
APP=""
CONFIG=""
FORCE_CONFIG=0
AGENT=1
while [ $# -gt 0 ]; do
	case "$1" in
	--binary) BINARY="$2"; shift 2 ;;
	--app) APP="$2"; shift 2 ;;
	--no-agent) AGENT=0; shift ;;
	--config) CONFIG="$2"; shift 2 ;;
	--force-config) FORCE_CONFIG=1; shift ;;
	-h|--help) sed -n '2,10p' "$0"; exit 0 ;;
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
if [ "$AGENT" -eq 1 ]; then
	if [ -z "$APP" ]; then
		for d in "$HERE/VPN Guard.app" "$ROOT/bin/darwin/VPN Guard.app"; do
			[ -d "$d" ] && { APP="$d"; break; }
		done
	fi
	[ -n "$APP" ] && [ -d "$APP" ] || die "VPN Guard.app not found; build with 'make darwin', pass --app or use --no-agent"
	AGENT_PLIST_SRC=$(first "$HERE/$AGENT_LABEL.plist" "$ROOT/deploy/darwin/$AGENT_LABEL.plist") || die "$AGENT_LABEL.plist not found"
fi

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

# 11. menu bar app (settings UI), started at every user login
if [ "$AGENT" -eq 1 ]; then
	CONSOLE_UID=$(stat -f %u /dev/console 2>/dev/null || echo 0)
	if [ "$CONSOLE_UID" -ne 0 ]; then
		launchctl bootout "gui/$CONSOLE_UID/$AGENT_LABEL" 2>/dev/null || true
	fi
	pkill -x vpn-guard-agent 2>/dev/null || true

	# macOS protects apps in /Applications ("App Management"): even root
	# gets "Operation not permitted" unless the terminal app is allowed in
	# System Settings > Privacy & Security > App Management. Do not abort
	# half-way: report it and restart whatever app is installed.
	AGENT_OK=1
	if [ -e "$APP_DST" ] && ! rm -rf "$APP_DST" 2>/tmp/vpn-guard-install.err; then
		AGENT_OK=0
	fi
	if [ "$AGENT_OK" -eq 1 ] && ! ditto "$APP" "$APP_DST" 2>>/tmp/vpn-guard-install.err; then
		AGENT_OK=0
	fi
	if [ "$AGENT_OK" -eq 1 ]; then
		chown -R root:wheel "$APP_DST"
		chmod -R go-w "$APP_DST"
		xattr -dr com.apple.quarantine "$APP_DST" 2>/dev/null || true
	fi
	install -o root -g wheel -m 0644 "$AGENT_PLIST_SRC" "$AGENT_PLIST_DST"
	if [ "$CONSOLE_UID" -ne 0 ] && [ -d "$APP_DST" ]; then
		launchctl bootstrap "gui/$CONSOLE_UID" "$AGENT_PLIST_DST" 2>/dev/null ||
			launchctl kickstart -k "gui/$CONSOLE_UID/$AGENT_LABEL" 2>/dev/null || true
	fi

	if [ "$AGENT_OK" -eq 1 ]; then
		rm -f /tmp/vpn-guard-install.err
		echo "VPN Guard menu bar app installed: $APP_DST (starts at login)"
	else
		echo >&2
		echo "error: could not replace $APP_DST:" >&2
		sed 's/^/  /' /tmp/vpn-guard-install.err >&2 || true
		echo >&2
		echo "macOS blocks changes to apps in /Applications unless the terminal has the" >&2
		echo "\"App Management\" permission. Allow it in:" >&2
		echo "  System Settings > Privacy & Security > App Management > (your terminal app)" >&2
		echo "then run this installer again. The daemon is already updated." >&2
		exit 1
	fi
fi
