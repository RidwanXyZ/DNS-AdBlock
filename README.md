# Cloudflare Blocklist Sync — Hagezi → Cloudflare

Repo template to sync selected Hagezi adblock lists to Cloudflare Zero Trust Gateway lists via GitHub Actions.

## Quickstart
1. Fork this repo.
2. In repo Settings → Secrets → Actions, add:
   - `CF_API_TOKEN` (or `API_TOKEN`) — permission: `Account.Gateway Lists: Read/Write`
   - `CF_ACCOUNT_ID` — Cloudflare Account ID
   - `CF_LIST_ID` — (optional) Cloudflare List ID for combined mode
   - For split mode, add `LIST_ID_GAMBLING`, `LIST_ID_PORN`, etc. (uppercase category)
3. Optionally edit `config/sources.json` to add/remove sources.
4. Trigger manually: `Actions → Sync Hagezi Blocklists → Run workflow` or wait schedule.

## Modes
- **Dry-run (default on schedule)** — workflow runs `--dry-run` on schedule and only prints sample.
- **Push** — manual or main-branch run pushes to Cloudflare.

## Notes
- Cloudflare custom lists accept plain domains only.
- Script strips/ignores non-domain rules (regex, path-based rules).
- If you need whitelist support, add `config/whitelist.txt` and modify script.