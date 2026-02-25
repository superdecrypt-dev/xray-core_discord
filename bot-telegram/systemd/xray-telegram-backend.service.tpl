[Unit]
Description=Xray Telegram Backend (FastAPI)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/bot-telegram/backend-py
EnvironmentFile=/etc/xray-telegram-bot/bot.env
ExecStart=/opt/bot-telegram/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
