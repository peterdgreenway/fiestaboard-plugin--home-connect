# Home Connect — Authorization Code Grant Flow

## Portal credentials

| Portal | Plugin |
|--------|--------|
| **API Web Client ID** | API Web Client ID |
| **Fiestaboard Client ID** | Fiestaboard Client ID |
| **Fiestaboard Client Secret** | Fiestaboard Client Secret |

Register the app with **OAuth Flow = Authorization Code Grant Flow**.  
**Redirect URI** in the portal must match the plugin (default `http://localhost`).

## Authorize once

1. Enter Client ID, Secret, and Redirect URI → **Save**
2. Open **`authorize_url`** from plugin data (or build from logs). Example shape:

```text
https://api.home-connect.com/security/oauth/authorize?response_type=code&client_id=...&redirect_uri=http://localhost&scope=IdentifyAppliance%20Monitor%20Control%20Settings
```

3. Sign in with your **personal** Home Connect account and **Allow**
4. Browser goes to e.g. `http://localhost/?code=XXXX` (page may fail to load — that is OK)
5. Copy the **code** (or whole URL) into **Authorization code**
6. Turn **Exchange authorization code** ON → **Save**
7. Tokens are stored encrypted; appliances should list on the next fetch

## Note

```
{{home_connect.note_row1}}
{{home_connect.note_row2}}
{{home_connect.note_row3}}
```

## Other features

- **Run refresh now** · auto refresh default **300 s**
- Monitor window **07:30–23:45** (UK)
- Up to **5** appliances · name filter · simulator · demo mode
- **Clear stored tokens** to force re-login
- `auth_status`: AUTHORIZED | NEEDS_CODE | …


## Manual tokens (priority order)

You may paste tokens from a Home Connect OAuth response:

| Priority | Setting | Behaviour |
|----------|---------|-----------|
| **1** | **refresh_token** | Exchanged for a new access_token (needs Client ID + Secret) |
| **2** | **id_token** | Used as Bearer if refresh is not available |
| **3** | **access_token** | Used as Bearer if neither of the above applies |

All three are **encrypted on Save**. **Clear stored tokens** wipes these fields too.


## Get tokens via OAuth (button)

1. Set **Fiestaboard Client ID**, **Secret**, and **Redirect URI** → Save  
2. Open **`authorize_url`** from plugin data → log in → Allow  
3. Copy `code` from the browser address bar into **Authorization code**  
4. Turn **Get tokens via OAuth** **ON** → **Save**  
5. Plugin stores **refresh_token**, **access_token**, and **id_token** (encrypted)  
6. Turn the button **OFF** after success (it clears automatically on success)
