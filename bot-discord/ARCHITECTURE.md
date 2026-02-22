# Bot Discord Architecture (Draft)

## Scope (Locked)
- Bot hanya untuk operasional Xray (mirror fungsi `manage.sh`).
- Tanpa fitur Git update/push.
- Tanpa token GitHub.

## Directory Tree
```text
/opt/xray-core_discord/bot-discord
├── README.md
├── install-discord-bot.sh
├── .env.example
├── gateway-ts/
│   ├── package.json
│   ├── tsconfig.json
│   ├── .env.example
│   └── src/
│       ├── index.ts
│       ├── config.ts
│       ├── authz.ts
│       ├── router.ts
│       ├── api_client.ts
│       ├── interactions/
│       │   ├── panel.ts
│       │   ├── buttons.ts
│       │   ├── selects.ts
│       │   └── modals.ts
│       └── views/
│           ├── main_menu.ts
│           ├── menu_1_status.ts
│           ├── menu_2_user.ts
│           ├── menu_3_quota.ts
│           ├── menu_4_network.ts
│           ├── menu_5_domain.ts
│           ├── menu_6_speedtest.ts
│           ├── menu_7_security.ts
│           ├── menu_8_maintenance.ts
│           └── menu_9_install_bot.ts
├── backend-py/
│   ├── requirements.txt
│   ├── .env.example
│   └── app/
│       ├── main.py
│       ├── config.py
│       ├── schemas.py
│       ├── auth.py
│       ├── bridge/
│       │   ├── shell_exec.py
│       │   └── manage_api_client.py
│       ├── services/
│       │   ├── menu_1_status.py
│       │   ├── menu_2_user.py
│       │   ├── menu_3_quota.py
│       │   ├── menu_4_network.py
│       │   ├── menu_5_domain.py
│       │   ├── menu_6_speedtest.py
│       │   ├── menu_7_security.py
│       │   ├── menu_8_maintenance.py
│       │   └── menu_9_install_bot.py
│       └── utils/
│           ├── locks.py
│           ├── validators.py
│           └── response.py
├── bridge/
│   ├── manage_api.sh
│   └── command_map.sh
├── shared/
│   ├── commands.json
│   └── error_codes.json
├── runtime/
│   ├── logs/
│   ├── locks/
│   └── tmp/
├── systemd/
│   ├── xray-discord-gateway.service
│   └── xray-discord-backend.service
└── scripts/
    ├── dev-up.sh
    ├── dev-down.sh
    └── smoke-test.sh
```

## Required Secrets / IDs

### Wajib
- `DISCORD_BOT_TOKEN`
- `DISCORD_APPLICATION_ID`
- `DISCORD_GUILD_ID`
- `INTERNAL_SHARED_SECRET`

### Opsional (Disarankan)
- `DISCORD_ADMIN_ROLE_ID`

## Security Notes
- Semua secret disimpan di `.env`, tidak hardcode.
- `manage_api.sh` wajib whitelist command yang boleh dieksekusi.
- Blok total command Git (`git add/commit/push/pull`) di bot layer dan backend layer.
