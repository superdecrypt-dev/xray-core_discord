[Unit]
Description=Xray Telegram Gateway (python-telegram-bot)
After=network-online.target xray-telegram-backend.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/bot-telegram/gateway-py
EnvironmentFile=/etc/xray-telegram-bot/bot.env
ExecStart=/opt/bot-telegram/.venv/bin/python -m app.main
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
