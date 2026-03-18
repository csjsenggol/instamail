# Instamail Web App

A Flask web application for creating and managing temporary email accounts using the mail.tm API.

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
- Simple web interface

## Note

This app uses the mail.tm service for temporary emails. Accounts are "permanent" but may be deleted by the service.