[Unit]
Description=Run Xray Discord Lightweight Monitor every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=20
Persistent=true
Unit=xray-discord-monitor.service

[Install]
WantedBy=timers.target

