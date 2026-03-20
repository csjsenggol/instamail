# Instamail Web App

A Flask web application for creating and managing temporary email accounts using Mail.tm API.

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

- Create temporary email accounts using Mail.tm
- View incoming messages
- Delete messages
- Shared account persistence using SQLite (`accounts.db`)
- Simple dark-themed web interface

## Configuration

This app uses Mail.tm API for account creation and email management.

For production on Render, attach a persistent disk and set `ACCOUNTS_DB_PATH` (example: `/var/data/accounts.db`) so account data survives deploys/restarts.