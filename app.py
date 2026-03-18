import datetime
import json
import os
import re
import requests
import secrets
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
# Use an environment variable for the session secret key in production
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_urlsafe(24))

# Persistent store for created accounts (survives server restart)
ACCOUNTS_FILE = os.path.join(os.path.dirname(__file__), 'accounts.json')


def load_accounts():
    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_accounts(accounts):
    try:
        with open(ACCOUNTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(accounts, f)
    except Exception:
        pass


# Load persistent accounts at startup
PERSISTENT_ACCOUNTS = load_accounts()

# In-memory cache of messages per account (keeps inbox visible across refreshes)
MESSAGE_CACHE = {}


def extract_otp(text):
    """Extract a 4-8 digit OTP/code from message text."""
    if not text:
        return None
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
    if 'active_email' not in session and session['accounts']:
        session['active_email'] = session['accounts'][0]['email']

    # allow switching active account via query param
    active = request.args.get('active')
    if active:
        session['active_email'] = active

    active_email = session.get('active_email')
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

            # Extract OTP codes (if any)
            msg['otp'] = extract_otp(msg.get('text') or msg.get('html') or '')

            # Show a short preview snippet in the inbox list
            raw_text = (msg.get('text') or msg.get('html') or '').strip().splitlines()
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

    return render_template('index.html', domains=domains, messages=messages, accounts=session['accounts'], active_email=active_email)

@app.route('/create_account', methods=['POST'])
def create_account():
    domain = request.form['domain']
    username = request.form['username']
    password = secrets.token_urlsafe(12)  # Generate a secure random password
    email = f"{username}@{domain}"
    mail = MailTM()
    response = mail.session.post(f"{mail.BASE_URL}/accounts", json={"address": email, "password": password})

    if response.status_code == 201:
        # Track multiple accounts in session
        accounts = session.get('accounts', [])
        accounts.append({'email': email, 'password': password})
        session['accounts'] = accounts
        session['active_email'] = email

        # Persist accounts across server restarts
        global PERSISTENT_ACCOUNTS
        PERSISTENT_ACCOUNTS = accounts
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

    otp_code = extract_otp(message.get('text') or message.get('html') or '')

    return render_template('message.html', message=message, active_email=active_email, otp_code=otp_code)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)