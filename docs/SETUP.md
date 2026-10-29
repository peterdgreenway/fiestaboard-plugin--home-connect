# Home Connect — Setup

OAuth flow: **Device Flow** (as set in the Home Connect developer portal).

## Portal credentials (names match Home Connect)

| Portal label | Plugin setting |
|--------------|----------------|
| **API Web Client ID** | API Web Client ID |
| **Fiestaboard Client ID** | Fiestaboard Client ID |
| **Fiestaboard Client Secret** | Fiestaboard Client Secret (encrypted on Save) |

Home Connect does **not** show long-lived token IDs in the portal. Tokens are obtained only via **Device Flow** and then stored encrypted by the plugin.

## Authorize (Device Flow)

1. Enter the three client values from the portal  
2. Turn **Start Device Flow (OAuth)** **ON**  
3. **Save Changes**  
4. Check plugin data / logs for:
   - `device_verify_uri` — open this URL  
   - `device_user_code` — enter this code and approve access  
5. After approval, the plugin stores refresh/access tokens and can list appliances  
6. You can turn **Start Device Flow** OFF once authorized (refresh token is kept)

## Note

```
{{home_connect.note_row1}}
{{home_connect.note_row2}}
{{home_connect.note_row3}}
```

Up to 5 appliances: `appliance_1_…` … `appliance_5_…`

## Refresh & monitoring

- **Run refresh now** + Save  
- Auto refresh default **300 s (5 min)**  
- Window **07:30–23:45** (UK local), configurable  

## Demo

**Demo mode** = sample data, no Home Connect login.
