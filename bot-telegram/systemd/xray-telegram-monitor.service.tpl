[Unit]
Description=Xray Telegram Lightweight Monitor
After=network-online.target xray-telegram-backend.service xray-telegram-gateway.service
Wants=network-online.target

[Service]
Type=oneshot
User=root
EnvironmentFile=/etc/xray-telegram-bot/bot.env
ExecStart=/opt/bot-telegram/scripts/monitor-lite.sh --quiet
