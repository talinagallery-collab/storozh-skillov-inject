#!/bin/bash
# Включить / выключить сторожа Inject (фоновая служба com.artais.inject-watch).
# Запускает человек сам:  bash vklyuchit-storozha.sh        — включить
#                         bash vklyuchit-storozha.sh off    — выключить и убрать
# Сторож только читает папки скиллов; раз в 5 минут и при изменении главных папок.
set -e
LABEL=com.artais.inject-watch
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DIR="$(cd "$(dirname "$0")" && pwd)"
ST="$HOME/Library/Application Support/artais-inject"
PROJECTS="${INJECT_PROJECTS:-$HOME/Documents/projects}"
HERMES="${INJECT_HERMES_SKILLS:-$HOME/.hermes/skills}"

if [ "$1" = "off" ]; then
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  echo "Сторож выключен. Журнал оставлен: $ST"
  exit 0
fi

mkdir -p "$ST"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>-c</string>
    <string>export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export INJECT_PROJECTS='$PROJECTS' INJECT_HERMES_SKILLS='$HERMES'; exec /usr/bin/env python3 "$DIR/inject_watch.py"</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>300</integer>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>WatchPaths</key>
  <array>
    <string>$HOME/.claude/skills</string>
    <string>$HOME/.codex/skills</string>
    <string>$HOME/.codex/plugins/cache</string>
    <string>$PROJECTS/.agents/skills</string>
    <string>$HERMES</string>
  </array>
  <key>StandardOutPath</key><string>$ST/launchd-out.log</string>
  <key>StandardErrorPath</key><string>$ST/launchd-err.log</string>
</dict>
</plist>
EOF
plutil -lint "$PLIST" >/dev/null
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
sleep 12
echo "Сторож включён. Последний прогон:"
tail -2 "$ST/launchd-out.log" 2>/dev/null || echo "  (ещё идёт — посмотри через минуту: tail \"$ST/launchd-out.log\")"
/usr/bin/osascript -e 'display notification "Сторож Inject включён — сообщу о каждом новом скилле" with title "Inject" sound name "Glass"' || true
