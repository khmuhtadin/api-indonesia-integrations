# API Indonesia integrations for Notion and Linear

A small Cloudflare Worker that brings Indonesian public holidays and cuti bersama (joint leave days from the SKB 3 Menteri) into Notion and Linear, using data from [API Indonesia](https://apiindonesia.id).

Live at **https://integrations.apiindonesia.id**

| Integration | What it does | Set up |
| --- | --- | --- |
| Notion | Creates a "Hari Libur Indonesia" database in a page you pick and fills it with this year's and next year's holidays. New dates are added daily. | https://integrations.apiindonesia.id/notion |
| Linear | Creates an issue labelled "Holiday" in a team you pick for each holiday in the next 14 days (7/30/60 also available), due on the holiday date. Checks daily. | https://integrations.apiindonesia.id/linear |

Each user brings their own API Indonesia key (create one at https://dashboard.apiindonesia.id). The key and the OAuth tokens are stored encrypted with AES-GCM; the encryption key only exists as a Worker secret. Privacy notes: https://integrations.apiindonesia.id/privacy

## How it works

- `GET /notion`, `GET /linear`: connect and docs pages. The form posts the API key, which is validated with one call to `GET /api/v1/libur`, stored encrypted against a random OAuth `state`, and the user is sent to the provider's OAuth screen.
- `/notion/callback`, `/linear/callback`: exchange the code, store the encrypted token, set a signed session cookie, then show a setup page (pick a Notion page, or a Linear team and look-ahead window).
- Cron (every 15 minutes): each install is synced once a day, plus any backlog. Rows/issues are deduplicated by the API Indonesia holiday id and never edited or deleted.
- When a token stops working (connection removed in Notion, app revoked in Linear) the install's stored data is deleted on the next sync.

## Deploy your own

```sh
npx wrangler d1 create api-indonesia-integrations   # put the id in wrangler.toml
npx wrangler d1 migrations apply api-indonesia-integrations --remote
openssl rand -base64 32 | npx wrangler secret put ENC_KEY
npx wrangler secret put NOTION_CLIENT_SECRET
npx wrangler secret put LINEAR_CLIENT_SECRET
npx wrangler deploy
```

Set `NOTION_CLIENT_ID`, `LINEAR_CLIENT_ID` and `BASE_URL` in `wrangler.toml`. Redirect URIs are `${BASE_URL}/notion/callback` and `${BASE_URL}/linear/callback`.

## License

MIT. Built by Khaisa Studio. Support: contactmuhtadin@gmail.com
