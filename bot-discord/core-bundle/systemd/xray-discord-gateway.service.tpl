[Unit]
Description=Xray Discord Gateway (TypeScript)
After=network.target

[Service]
Type=simple
WorkingDirectory=__GATEWAY_DIR__
ExecStart=/usr/bin/env bash -lc 'npm run dev'
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
