[Unit]
Description=Xray Discord Gateway (discord.js)
After=network-online.target xray-discord-backend.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/bot-discord/gateway-ts
EnvironmentFile=/etc/xray-discord-bot/bot.env
ExecStart=/usr/bin/node /opt/bot-discord/gateway-ts/dist/index.js
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
