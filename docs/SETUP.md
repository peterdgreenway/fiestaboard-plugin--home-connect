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


## Rate limits & caching (v2.5)

Home Connect allows about **1000 API calls per day**. Each poll previously could call:

- 1 × list appliances  
- 3 × per appliance (status + active program + options)

With 2 devices every few minutes that exceeds the daily limit.

### Changes

1. **Max poll every 5 minutes** (`refresh_seconds` minimum 300)  
2. **In-memory cache** — repeat polls within 5 minutes reuse last data (no API)  
3. **Access token** refreshed only when near expiry (or missing), via `refresh_token`  
4. **HTTP 429** — reads `Retry-After` when present; suspends calls (for daily limit, until next UTC midnight)  
5. **Idle devices** — only `/status`; active program endpoints only when OperationState looks running  
6. **Errors / rate limit** — UI keeps **last successful** appliance values (`data_stale=YES`)  

### Server-Sent Events (SSE)

Home Connect offers `GET /api/homeappliances/events` (SSE) for push updates. FiestaBoard plugins are **pull-based** (`fetch_data` on a timer), so a long-lived SSE client is not used in this build. Polling at ≤1/5 min with caching is the supported approach; SSE would need a side process outside the plugin poll model.


## API budget & discovery cache (v2.6)

| Mechanism | Detail |
|-----------|--------|
| **Discovery cache** | `/api/homeappliances` at most every **6 hours** (or on Run refresh now) |
| **Programme calls** | Only if OperationState is active **and** remaining time not already on status |
| **Daily budget** | Hard stop at **900** counted API requests/UTC day (under 1000 limit) |
| **Per idle appliance** | **1** call (`/status`) per poll cycle |


## Persistent state (v2.7)

Budget, rate-limit suspension, access-token cache (with **2-minute** refresh margin), discovery cache, and last appliance snapshot are stored in:

```text
$FIESTABOARD_APP_DATA/home_connect_state.json
```

Override with:

```bash
export HOME_CONNECT_STATE_PATH=/app_data/home_connect_state.json
```

Mount this file/dir in Docker so container restarts keep the daily counter.
