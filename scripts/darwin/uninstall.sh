#!/bin/sh
# VPN Guard uninstaller for macOS.
#
#   sudo ./uninstall.sh [--purge]
#
# --purge also removes /etc/vpn-guard and the log files.
set -eu

LABEL="com.vpnguard.daemon"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(uname -s)" = "Darwin" ] || { echo "this uninstaller is for macOS" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

launchctl bootout "system/$LABEL" 2>/dev/null || true
CONSOLE_UID=$(stat -f %u /dev/console 2>/dev/null || echo 0)
[ "$CONSOLE_UID" -ne 0 ] && launchctl bootout "gui/$CONSOLE_UID/com.vpnguard.agent" 2>/dev/null || true
pkill -x vpn-guard-agent 2>/dev/null || true
rm -f /Library/LaunchAgents/com.vpnguard.agent.plist
rm -rf "/Applications/VPN Guard.app"
rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -f /usr/local/bin/vpn-guard
rm -f /var/run/vpn-guard.sock

if [ "$PURGE" -eq 1 ]; then
	rm -rf /etc/vpn-guard
	rm -f /var/log/vpn-guard.log /var/log/vpn-guard.log.* /var/log/vpn-guard-error.log
	echo "vpn-guard removed (configuration and logs purged)"
else
	echo "vpn-guard removed (kept /etc/vpn-guard and /var/log/vpn-guard*.log; use --purge to delete)"
fi
