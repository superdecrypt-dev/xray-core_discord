[Unit]
Description=Xray Discord Lightweight Monitor
After=network-online.target xray-discord-backend.service xray-discord-gateway.service
Wants=network-online.target

[Service]
Type=oneshot
User=root
EnvironmentFile=/etc/xray-discord-bot/bot.env
ExecStart=/opt/bot-discord/scripts/monitor-lite.sh --quiet

