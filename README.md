# PHP2Shell checker

Passive check for [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp), plus an optional quote form. This is the site at [puparazee.com](https://puparazee.com).

The checker sends one HEAD request and, when that connects, a short GET of `/wp-json/`. It does not send exploit payloads. Private and reserved addresses are refused.

## Develop

```bash
npm install
npm test
npm run dev
```

## Vercel environment

| Name | Required | Purpose |
| --- | --- | --- |
| `RESEND_API_KEY` | Yes, for the quote form | Sends the lead to marc.smith@mail.grokbot.com. If it is missing, the form returns 503 and does not drop the lead silently. |
| `RESEND_FROM` | No | From address. Defaults to `PHP2Shell Checker <onboarding@resend.dev>`. After puparazee.com is verified in Resend, set `PHP2Shell Checker <noreply@puparazee.com>`. |
