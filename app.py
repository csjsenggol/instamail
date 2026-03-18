import datetime
import json
import math
import os
import re
import sqlite3
import requests
import secrets
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
# Use an environment variable for the session secret key in production
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_urlsafe(24))

# Persistent store for created accounts (survives server restart)
ACCOUNTS_DB = os.getenv('ACCOUNTS_DB_PATH', os.path.join(os.path.dirname(__file__), 'accounts.db'))
LEGACY_ACCOUNTS_FILE = os.path.join(os.path.dirname(__file__), 'accounts.json')


def get_db_connection():
    return sqlite3.connect(ACCOUNTS_DB)


def init_accounts_db():
    """Create accounts table and migrate legacy JSON data once if needed."""
    try:
        with get_db_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )

            existing_count = conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
            if existing_count == 0 and os.path.exists(LEGACY_ACCOUNTS_FILE):
                try:
                    with open(LEGACY_ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                        legacy_accounts = json.load(f)
                except Exception:
                    legacy_accounts = []

                for account in legacy_accounts:
                    if not isinstance(account, dict):
                        continue
                    email = account.get('email')
                    password = account.get('password')
                    if not email or not password:
                        continue
                    conn.execute(
                        "INSERT OR IGNORE INTO accounts (email, password) VALUES (?, ?)",
                        (email, password),
                    )
    except Exception:
        # Keep app running even if DB setup fails; callers fall back to empty list.
        pass


def load_accounts():
    try:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT email, password FROM accounts ORDER BY id ASC"
            ).fetchall()
        return [{'email': email, 'password': password} for email, password in rows]
    except Exception:
        return []


def save_accounts(accounts):
    """Persist account list to DB (upsert by email) and keep insertion order."""
    try:
        with get_db_connection() as conn:
            for account in accounts or []:
                if not isinstance(account, dict):
                    continue
                email = account.get('email')
                password = account.get('password')
                if not email or not password:
                    continue
                conn.execute(
                    "INSERT OR IGNORE INTO accounts (email, password) VALUES (?, ?)",
                    (email, password),
                )
    except Exception:
        pass


def save_account(email, password):
    """Persist a single account if it does not already exist."""
    if not email or not password:
        return
    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO accounts (email, password) VALUES (?, ?)",
                (email, password),
            )
    except Exception:
        pass


def merge_account_lists(preferred_accounts, fallback_accounts):
    """Merge account lists by email, keeping preferred order and removing duplicates."""
    merged = []
    seen = set()

    for source in (preferred_accounts or [], fallback_accounts or []):
        for account in source:
            email = account.get('email') if isinstance(account, dict) else None
            password = account.get('password') if isinstance(account, dict) else None
            if not email or not password or email in seen:
                continue
            merged.append({'email': email, 'password': password})
            seen.add(email)

    return merged


# Initialize DB and load persistent accounts at startup
init_accounts_db()
PERSISTENT_ACCOUNTS = load_accounts()

# In-memory cache of messages per account (keeps inbox visible across refreshes)
MESSAGE_CACHE = {}


def extract_otp(text):
    """Extract a 4-8 digit OTP/code from message text."""
    if not text:
        return None

    # Some providers return non-string payloads (e.g. HTML arrays/objects).
    if isinstance(text, list):
        text = " ".join(str(part) for part in text)
    else:
        text = str(text)

    # Prefer numbers close to OTP/code-related keywords.
    keyword_patterns = [
        r"(?:otp|verification\s*code|verify\s*code|auth(?:entication)?\s*code|security\s*code|one[-\s]*time\s*(?:pass(?:word)?|code)|code)\s*[:#-]?\s*(\d{4,8})\b",
        r"\b(\d{4,8})\b\s*(?:is\s*(?:your|the)?\s*)?(?:otp|verification\s*code|verify\s*code|auth(?:entication)?\s*code|security\s*code|one[-\s]*time\s*(?:pass(?:word)?|code)|code)\b",
    ]

    for pattern in keyword_patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1)

    # Fallback: first standalone 4-8 digit number.
    match = re.search(r"\b(\d{4,8})\b", text)
    return match.group(1) if match else None

class MailTM:
    BASE_URL = "https://api.mail.tm"

    def __init__(self):
        self.session = requests.Session()

    def get_domains(self):
        """Fetch the list of active domains."""
        response = self.session.get(f"{self.BASE_URL}/domains")
        return [d['domain'] for d in response.json()['hydra:member']]

    def create_account(self, email, password):
        """Create a new 'permanent' email account."""
        data = {"address": email, "password": password}
        response = self.session.post(f"{self.BASE_URL}/accounts", json=data)
        return response.status_code == 201

    def get_token(self, email, password):
        """Login to get the Bearer token (required for reading mail)."""
        data = {"address": email, "password": password}
        response = self.session.post(f"{self.BASE_URL}/token", json=data)
        if response.status_code == 200:
            return response.json()['token']
        return None

    def get_messages(self, token):
        """Fetch all messages for the account."""
        headers = {"Authorization": f"Bearer {token}"}
        response = self.session.get(f"{self.BASE_URL}/messages", headers=headers)
        return response.json()['hydra:member']

    def get_message(self, token, message_id):
        """Fetch a single message by ID."""
        headers = {"Authorization": f"Bearer {token}"}
        response = self.session.get(f"{self.BASE_URL}/messages/{message_id}", headers=headers)
        if response.status_code == 200:
            return response.json()
        return None

    def delete_message(self, token, message_id):
        """Delete a message by ID."""
        headers = {"Authorization": f"Bearer {token}"}
        response = self.session.delete(f"{self.BASE_URL}/messages/{message_id}", headers=headers)
        return response.status_code == 204

@app.route('/')
def index():
    mail = MailTM()
    domains = mail.get_domains()

    # Ensure session state for multiple accounts
    if 'accounts' not in session:
        session['accounts'] = PERSISTENT_ACCOUNTS.copy()

    # Keep each browser session synced with the latest shared accounts.
    persisted_accounts = load_accounts()
    session_accounts = session.get('accounts', [])
    merged_accounts = merge_account_lists(persisted_accounts, session_accounts)
    if merged_accounts != session_accounts:
        session['accounts'] = merged_accounts

    if 'active_email' not in session and session.get('accounts'):
        session['active_email'] = session['accounts'][0]['email']

    # allow switching active account via query param
    active = request.args.get('active')
    if active:
        session['active_email'] = active

    account_emails = {a['email'] for a in session.get('accounts', []) if isinstance(a, dict) and a.get('email')}
    if session.get('active_email') and session['active_email'] not in account_emails:
        session['active_email'] = session['accounts'][0]['email'] if session.get('accounts') else None

    active_email = session.get('active_email')
    all_accounts = list(reversed(session.get('accounts', [])))

    # Paginate accounts in sidebar: newest first, 100 per page.
    account_per_page = 100
    account_total = len(all_accounts)
    account_total_pages = max(1, math.ceil(account_total / account_per_page))
    account_page = request.args.get('account_page', default=1, type=int)
    if account_page < 1:
        account_page = 1
    if account_page > account_total_pages:
        account_page = account_total_pages

    account_start_idx = (account_page - 1) * account_per_page
    account_end_idx = account_start_idx + account_per_page

    paginated_accounts = []
    for account in all_accounts[account_start_idx:account_end_idx]:
        account_copy = dict(account)
        email = account_copy.get('email', '')
        account_copy['display_email'] = f"{email[:20]}..." if len(email) > 20 else email
        paginated_accounts.append(account_copy)

    messages = []

    # Show all messages from all accounts together, but keep the active account selected in the sidebar.
    for account in session.get('accounts', []):
        account_email = account['email']
        cached_msgs = MESSAGE_CACHE.get(account_email, [])

        token = mail.get_token(account_email, account['password'])
        if not token:
            # If we can't log in, fall back to cached messages for that account
            messages.extend(cached_msgs)
            continue

        try:
            raw_msgs = mail.get_messages(token)
        except Exception:
            raw_msgs = []

        formatted_msgs = []
        for msg in raw_msgs:
            # Format timestamps for display
            created_at = msg.get('createdAt')
            formatted_date = None
            if created_at:
                try:
                    dt = datetime.datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    formatted_date = dt.strftime('%b %d, %H:%M')
                except Exception:
                    formatted_date = created_at
            msg['formatted_date'] = formatted_date

            # Extract OTP codes (if any) from all useful fields.
            otp_source = " ".join(
                str(part)
                for part in [
                    msg.get('subject', ''),
                    msg.get('intro', ''),
                    msg.get('text', ''),
                    msg.get('html', ''),
                ]
                if part
            )
            msg['otp'] = extract_otp(otp_source)

            # Show a short preview snippet in the inbox list
            raw_text = (msg.get('text') or msg.get('intro') or msg.get('html') or '').strip().splitlines()
            snippet = raw_text[0] if raw_text else ''
            msg['snippet'] = (snippet[:80] + '...') if len(snippet) > 80 else snippet

            # Tag message with its account so user can see which inbox it came from
            msg['account'] = account_email

            formatted_msgs.append(msg)

        # Cache messages per account for fallbacks
        if formatted_msgs:
            MESSAGE_CACHE[account_email] = formatted_msgs
            messages.extend(formatted_msgs)
        else:
            messages.extend(cached_msgs)

    # Sort the combined inbox by date (most recent first)
    def _msg_date(m):
        try:
            return datetime.datetime.fromisoformat((m.get('createdAt') or '').replace('Z', '+00:00'))
        except Exception:
            return datetime.datetime.min

    messages.sort(key=_msg_date, reverse=True)

    # Paginate inbox list: 100 messages per page.
    per_page = 100
    total_messages = len(messages)
    total_pages = max(1, math.ceil(total_messages / per_page))
    page = request.args.get('page', default=1, type=int)
    if page < 1:
        page = 1
    if page > total_pages:
        page = total_pages

    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_messages = messages[start_idx:end_idx]

    return render_template(
        'index.html',
        domains=domains,
        messages=paginated_messages,
        accounts=paginated_accounts,
        active_email=active_email,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_messages=total_messages,
        start_index=start_idx + 1 if total_messages else 0,
        end_index=min(end_idx, total_messages),
        account_page=account_page,
        account_total=account_total,
        account_total_pages=account_total_pages,
        account_start_index=account_start_idx + 1 if account_total else 0,
        account_end_index=min(account_end_idx, account_total),
    )

@app.route('/create_account', methods=['POST'])
def create_account():
    domain = request.form['domain']
    username = request.form['username']
    password = secrets.token_urlsafe(12)  # Generate a secure random password
    email = f"{username}@{domain}"
    mail = MailTM()
    response = mail.session.post(f"{mail.BASE_URL}/accounts", json={"address": email, "password": password})

    if response.status_code == 201:
        # Merge with latest shared state to avoid overwriting accounts from other users/devices.
        latest_accounts = load_accounts()
        if not any(a.get('email') == email for a in latest_accounts):
            latest_accounts.append({'email': email, 'password': password})

        session_accounts = session.get('accounts', [])
        session['accounts'] = merge_account_lists(latest_accounts, session_accounts)
        session['active_email'] = email

        # Persist accounts across server restarts
        global PERSISTENT_ACCOUNTS
        PERSISTENT_ACCOUNTS = latest_accounts
        save_accounts(PERSISTENT_ACCOUNTS)

        return redirect(url_for('index'))
    elif response.status_code == 400:
        error_msg = "Invalid email address or account already exists. Please try a different username."
    elif response.status_code == 422:
        error_msg = "Unprocessable entity. Check the email format."
    elif response.status_code >= 500:
        error_msg = "Server error. Please try again later."
    else:
        error_msg = f"Failed to create account (Status: {response.status_code}). Please try again."

    domains = mail.get_domains()
    return render_template('index.html', domains=domains, error=error_msg, accounts=session.get('accounts', []), active_email=session.get('active_email'))

@app.route('/messages/action', methods=['POST'])
def messages_action():
    """Perform bulk actions on messages (delete)."""
    action = request.form.get('action')
    message_ids = request.form.getlist('message_ids')
    active_email = session.get('active_email')
    if not active_email or not message_ids:
        return redirect(url_for('index'))

    active_account = next((a for a in session.get('accounts', []) if a['email'] == active_email), None)
    if not active_account:
        return redirect(url_for('index'))

    mail = MailTM()
    token = mail.get_token(active_account['email'], active_account['password'])
    if not token:
        return redirect(url_for('index'))

    if action == 'delete':
        for mid in message_ids:
            mail.delete_message(token, mid)
            if active_email in MESSAGE_CACHE:
                MESSAGE_CACHE[active_email] = [m for m in MESSAGE_CACHE[active_email] if m.get('id') != mid]

    return redirect(url_for('index'))

@app.route('/message/<message_id>')
def view_message(message_id):
    active_email = session.get('active_email')
    if not active_email:
        return redirect(url_for('index'))

    active_account = next((a for a in session.get('accounts', []) if a['email'] == active_email), None)
    if not active_account:
        return redirect(url_for('index'))

    mail = MailTM()
    token = mail.get_token(active_account['email'], active_account['password'])
    if not token:
        return redirect(url_for('index'))

    message = mail.get_message(token, message_id)
    if not message:
        # Fall back to cached messages if the API can't return the message (e.g., rate limit)
        message = next((m for m in MESSAGE_CACHE.get(active_email, []) if m.get('id') == message_id), None)

    if not message:
        return redirect(url_for('index'))

    otp_source = " ".join(
        str(part)
        for part in [
            message.get('subject', ''),
            message.get('intro', ''),
            message.get('text', ''),
            message.get('html', ''),
        ]
        if part
    )
    otp_code = extract_otp(otp_source)

    return render_template('message.html', message=message, active_email=active_email, otp_code=otp_code)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)