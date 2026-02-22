[Unit]
Description=Xray Discord Backend (Python)
After=network.target

[Service]
Type=simple
WorkingDirectory=__BACKEND_DIR__
ExecStart=/usr/bin/env bash -lc '. .venv/bin/activate && uvicorn app.main:app --host 127.0.0.1 --port 8787'
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
