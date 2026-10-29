# Home Connect — Setup

Vestaboard **Note** (15×3) status for up to **5** Home Connect appliances.

## Security

- **Username** stored as plain identity (email).
- **Password**, **client secret**, and **refresh token** are **encrypted on Save** (Fernet).
- Prefer setting env `HOME_CONNECT_FERNET_KEY` or `FIESTABOARD_SECRET_KEY` (passphrase or 44-char Fernet key) so encryption is stable across restarts/hosts.

Production Home Connect apps usually need **OAuth authorization code → refresh_token**. Password grant works mainly on the **simulator**.

## Note (primary = first appliance)

```
{{home_connect.note_row1}}
{{home_connect.note_row2}}
{{home_connect.note_row3}}
```

Per appliance (1–5):

```
{{home_connect.appliance_1_note_row1}}
{{home_connect.appliance_1_note_row2}}
{{home_connect.appliance_1_note_row3}}
```

## Abridgment

Status text is shortened with rule-based “AI-style” abridgment to **≤15 characters** per Note line (operation state → short labels, minutes → `m`, etc.).

## Settings

| Setting | Purpose |
|---------|---------|
| User identity | Home Connect email |
| Password | Encrypted on save |
| Client ID / secret | Developer portal app |
| Refresh token | Recommended for live API |
| Simulator | Use simulator host |
| Demo mode | 5 sample devices, no login |
| Appliance filter | Optional name substrings |

## Install

```bash
curl -X POST http://localhost:4420/api/plugins/install \
  -H "Content-Type: application/json" \
  -d '{"repository": "https://github.com/peterdgreenway/fiestaboard-plugin--home-connect"}'
```

Plugin id: `home_connect` · Author: **peterdgreenway**
