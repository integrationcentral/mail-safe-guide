# Mail Safe Guide

A blunt, plain-English email authentication wizard for people who are afraid of DNS. It checks DMARC, SPF, DKIM, and MX; inventories sending platforms such as GoHighLevel, Kajabi, MailerLite, and ActiveCampaign; and walks users from sender authentication through staged DMARC enforcement.

## Run locally

Requires Node.js 20 or newer.

```bash
npm start
```

Open `http://localhost:3000`.

## Deploy to Railway from GitHub

1. Create an empty GitHub repository and push this folder to it.
2. In Railway, choose **New Project → Deploy from GitHub repo**.
3. Select the repository. Railway reads `railway.json` and starts the app automatically.
4. In the Railway service, open **Settings → Networking → Generate Domain**.

No database, secrets, or environment variables are required. The live checker performs public DNS lookups and stores nothing.

## Important scope

The guide intentionally starts DMARC at `p=none`. Users should inventory and authenticate all legitimate senders with SPF and/or DKIM before moving through current testing mode to quarantine or reject.
