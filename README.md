# Instamail Web App

A Flask web application for creating and managing temporary email accounts using Mail.tm and Mailinator APIs.

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the app:
   ```
   python app.py
   ```

3. Open your browser to `http://127.0.0.1:5000/`

## Features

- Create temporary email accounts
- View incoming messages
- Multi-provider domain support (Mail.tm + Mailinator)
- Shared account persistence using SQLite (`accounts.db`)
- Simple web interface

## Note

This app uses Mail.tm (primary) and Mailinator (public inbox) services.

Mailinator notes:
- Public inboxes are mailbox-on-demand (no explicit account creation).
- Message deletion is not supported in this app flow for public inboxes.
- Optionally set `MAILINATOR_API_KEY` for higher API access limits.
- Optional domains env: `MAILINATOR_DOMAINS` (default: `mailinator.com`).

Addy.io note:
- Addy.io is an alias-forwarding service and does not provide the same in-app inbox retrieval flow used here.
- It is not integrated as an inbox provider in this app.

For production on Render, attach a persistent disk and set `ACCOUNTS_DB_PATH` (example: `/var/data/accounts.db`) so account data survives deploys/restarts.