import datetime
import json
import math
import os
import re
import sqlite3
import requests
import secrets
import time
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

app = Flask(__name__)
# Use an environment variable for the session secret key in production
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_urlsafe(24))


@app.after_request
def add_no_cache_headers(response):
    # Ensure account list updates are visible immediately after redirects.
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


def build_url(**kwargs):
    """Build a clean index URL, omitting params that equal their defaults (page=1, account_page=1, scope='active')."""
    defaults = {'page': 1, 'account_page': 1, 'scope': 'active'}
    clean = {k: v for k, v in kwargs.items()
             if v is not None and defaults.get(k) != v}
    return url_for('index', **clean)

app.jinja_env.globals['build_url'] = build_url

# Rate limiting: track account creation attempts per session
ACCOUNT_CREATION_COOLDOWN = 2  # seconds between account creation attempts
LAST_ACCOUNT_CREATION = {}  # {session_id: timestamp}

# Persistent store for created accounts (survives server restart)
ACCOUNTS_DB = os.getenv('ACCOUNTS_DB_PATH', os.path.join(os.path.dirname(__file__), 'accounts.db'))
LEGACY_ACCOUNTS_FILE = os.path.join(os.path.dirname(__file__), 'accounts.json')

# Supported temporary-email APIs.
MAIL_PROVIDERS = {
    'mailtm': {
        'name': 'Mail.tm',
        'base_url': 'https://api.mail.tm',
        'type': 'hydra',
    },
    'mailinator': {
        'name': 'Mailinator',
        'base_url': 'https://api.mailinator.com/v2',
        'type': 'mailinator',
    },
}


def normalize_provider(provider_id):
    if provider_id in MAIL_PROVIDERS:
        return provider_id
    return 'mailtm'


def provider_name(provider_id):
    normalized = normalize_provider(provider_id)
    return MAIL_PROVIDERS[normalized]['name']


def account_cache_key(provider_id, email):
    return f"{normalize_provider(provider_id)}::{email}"


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
                    provider TEXT NOT NULL DEFAULT 'mailtm',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )

            columns = {row[1] for row in conn.execute("PRAGMA table_info(accounts)").fetchall()}
            if 'provider' not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN provider TEXT NOT NULL DEFAULT 'mailtm'")

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
                    provider = normalize_provider(account.get('provider'))
                    if not email or not password:
                        continue
                    conn.execute(
                        "INSERT OR IGNORE INTO accounts (email, password, provider) VALUES (?, ?, ?)",
                        (email, password, provider),
                    )
    except Exception:
        # Keep app running even if DB setup fails; callers fall back to empty list.
        pass


def load_accounts():
    try:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT email, password, provider FROM accounts ORDER BY id ASC"
            ).fetchall()
        return [
            {
                'email': email,
                'password': password,
                'provider': normalize_provider(provider),
            }
            for email, password, provider in rows
        ]
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
                provider = normalize_provider(account.get('provider'))
                if not email or not password:
                    continue
                conn.execute(
                    "INSERT OR IGNORE INTO accounts (email, password, provider) VALUES (?, ?, ?)",
                    (email, password, provider),
                )
    except Exception:
        pass


def save_account(email, password, provider='mailtm'):
    """Persist a single account if it does not already exist."""
    if not email or not password:
        return
    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO accounts (email, password, provider) VALUES (?, ?, ?)",
                (email, password, normalize_provider(provider)),
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
            provider = normalize_provider(account.get('provider')) if isinstance(account, dict) else 'mailtm'
            account_key = (provider, email)
            if not email or not password or account_key in seen:
                continue
            merged.append({'email': email, 'password': password, 'provider': provider})
            seen.add(account_key)

    return merged


# Initialize DB and load persistent accounts at startup
init_accounts_db()
PERSISTENT_ACCOUNTS = load_accounts()

# In-memory cache of messages per account (keeps inbox visible across refreshes)
MESSAGE_CACHE = {}
DOMAIN_CACHE_TTL_SECONDS = 300
DOMAIN_CACHE = {
    'expires_at': 0,
    'data': [],
}


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


def parse_message_datetime(value):
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None

    try:
        return datetime.datetime.fromisoformat(text.replace('Z', '+00:00'))
    except Exception:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.datetime.strptime(text, fmt)
        except Exception:
            continue

    return None

class MailProvider:
    def __init__(self, provider_id='mailtm'):
        self.provider_id = normalize_provider(provider_id)
        self.config = MAIL_PROVIDERS[self.provider_id]
        self.base_url = self.config['base_url']
        self.provider_type = self.config.get('type', 'hydra')
        self.session = requests.Session()

    def _parse_email(self, email):
        if not email or '@' not in email:
            return None, None
        local, domain = email.split('@', 1)
        return local, domain

    def _mailinator_domain_key(self, domain):
        # Public mailinator.com inboxes use the special domain key "public".
        return 'public' if (domain or '').lower() == 'mailinator.com' else (domain or '')

    def _mailinator_params(self):
        token = os.getenv('MAILINATOR_API_KEY', '').strip()
        return {'token': token} if token else {}

    def get_domains(self):
        """Fetch the list of active domains."""
        if self.provider_type == 'mailinator':
            domains = [d.strip() for d in os.getenv('MAILINATOR_DOMAINS', 'mailinator.com').split(',')]
            return [d for d in domains if d]

        response = self.session.get(f"{self.base_url}/domains", timeout=10)
        if response.status_code != 200:
            return []
        data = response.json().get('hydra:member', [])
        return [d.get('domain') for d in data if isinstance(d, dict) and d.get('domain')]

    def create_account(self, email, password):
        """Create account and return (success, status_code, actual_email)."""
        if self.provider_type == 'mailinator':
            local, domain = self._parse_email(email)
            allowed_domains = set(self.get_domains())
            if not local or not domain or domain not in allowed_domains:
                return False, 422, None
            # Mailinator public inboxes are mailbox-on-demand.
            return True, 201, None

        data = {"address": email, "password": password}
        response = self.session.post(f"{self.base_url}/accounts", json=data, timeout=10)
        return response.status_code == 201, response.status_code, None

    def get_token(self, email, password):
        """Login to get the Bearer token (required for reading mail)."""
        if self.provider_type == 'mailinator':
            return email

        data = {"address": email, "password": password}
        response = self.session.post(f"{self.base_url}/token", json=data, timeout=10)
        if response.status_code == 200:
            return response.json()['token']
        return None

    def get_messages(self, token):
        """Fetch all messages for the account."""
        if self.provider_type == 'mailinator':
            local, domain = self._parse_email(token)
            if not local or not domain:
                return []

            domain_key = self._mailinator_domain_key(domain)
            response = self.session.get(
                f"{self.base_url}/domains/{domain_key}/inboxes/{local}",
                params=self._mailinator_params(),
                timeout=10,
            )
            if response.status_code != 200:
                return []

            payload = response.json() if isinstance(response.json(), dict) else {}
            raw_msgs = payload.get('msgs', [])
            normalized = []
            for msg in raw_msgs:
                if not isinstance(msg, dict):
                    continue

                sender = msg.get('from') or msg.get('fromfull') or ''
                subject = msg.get('subject') or '(No subject)'
                msg_id = msg.get('id') or msg.get('msgid')
                created_raw = msg.get('time')

                created_at = None
                try:
                    if created_raw is not None:
                        ts = int(created_raw)
                        if ts > 9999999999:
                            ts = ts / 1000.0
                        created_at = datetime.datetime.utcfromtimestamp(ts).isoformat()
                except Exception:
                    created_at = str(created_raw) if created_raw is not None else None

                normalized.append(
                    {
                        'id': msg_id,
                        'subject': subject,
                        'createdAt': created_at,
                        'intro': msg.get('intro', ''),
                        'text': '',
                        'html': '',
                        'from': {
                            'address': sender,
                            'name': sender,
                        },
                        'to': [{'address': token}],
                    }
                )

            return normalized

        headers = {"Authorization": f"Bearer {token}"}
        response = self.session.get(f"{self.base_url}/messages", headers=headers, timeout=10)
        if response.status_code != 200:
            return []
        return response.json().get('hydra:member', [])

    def get_message(self, token, message_id):
        """Fetch a single message by ID."""
        if self.provider_type == 'mailinator':
            local, domain = self._parse_email(token)
            if not local or not domain:
                return None

            domain_key = self._mailinator_domain_key(domain)
            response = self.session.get(
                f"{self.base_url}/domains/{domain_key}/inboxes/{local}/messages/{message_id}",
                params=self._mailinator_params(),
                timeout=10,
            )
            if response.status_code != 200:
                return None

            payload = response.json() if isinstance(response.json(), dict) else {}
            data = payload.get('data', payload)
            if not isinstance(data, dict):
                return None

            parts = data.get('parts', [])
            text_body = ''
            html_body = ''
            if isinstance(parts, list):
                for part in parts:
                    if not isinstance(part, dict):
                        continue
                    body = part.get('body') or ''
                    content_type = (part.get('headers', {}).get('content-type') or '').lower()
                    if 'html' in content_type and not html_body:
                        html_body = body
                    elif 'text/plain' in content_type and not text_body:
                        text_body = body

            if not text_body:
                text_body = data.get('text', '') or data.get('subject', '')
            if not html_body:
                html_body = data.get('html', '')

            created_raw = data.get('time')
            created_at = None
            try:
                if created_raw is not None:
                    ts = int(created_raw)
                    if ts > 9999999999:
                        ts = ts / 1000.0
                    created_at = datetime.datetime.utcfromtimestamp(ts).isoformat()
            except Exception:
                created_at = str(created_raw) if created_raw is not None else None

            sender = data.get('from') or data.get('fromfull') or ''
            return {
                'id': data.get('id') or message_id,
                'subject': data.get('subject') or '(No subject)',
                'createdAt': created_at,
                'intro': '',
                'text': text_body,
                'html': html_body,
                'from': {
                    'address': sender,
                    'name': sender,
                },
                'to': [{'address': token}],
            }

        headers = {"Authorization": f"Bearer {token}"}
        response = self.session.get(f"{self.base_url}/messages/{message_id}", headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        return None

    def delete_message(self, token, message_id):
        """Delete a message by ID."""
        if self.provider_type == 'mailinator':
            # Public Mailinator inbox messages cannot be reliably deleted via this app flow.
            return False

        headers = {"Authorization": f"Bearer {token}"}
        response = self.session.delete(f"{self.base_url}/messages/{message_id}", headers=headers, timeout=10)
        return response.status_code == 204


def get_combined_domains(force_refresh=False):
    now = time.time()
    if not force_refresh and DOMAIN_CACHE['data'] and now < DOMAIN_CACHE['expires_at']:
        return DOMAIN_CACHE['data']

    domains = []
    for provider_id, config in MAIL_PROVIDERS.items():
        provider_client = MailProvider(provider_id)
        try:
            provider_domains = provider_client.get_domains()
        except Exception:
            provider_domains = []

        for domain in provider_domains:
            domains.append(
                {
                    'value': f"{provider_id}::{domain}",
                    'domain': domain,
                    'provider': provider_id,
                    'provider_name': config['name'],
                    'label': f"{domain} ({config['name']})",
                }
            )

    domains.sort(key=lambda item: item['domain'])
    DOMAIN_CACHE['data'] = domains
    DOMAIN_CACHE['expires_at'] = now + DOMAIN_CACHE_TTL_SECONDS
    return domains

@app.route('/')
def index():
    domains = get_combined_domains()
    just_created = request.args.get('created') == '1'
    account_exists_notice = request.args.get('exists') == '1'
    error = None
    inbox_scope = (request.args.get('scope') or 'active').lower()
    if inbox_scope not in ('active', 'all'):
        inbox_scope = 'active'

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
    if account_exists_notice and active_email:
        error = (
            f"Account {active_email} already exists. "
            "Showing the existing inbox messages."
        )

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
        provider = normalize_provider(account_copy.get('provider'))
        account_copy['display_email'] = f"{email[:20]}..." if len(email) > 20 else email
        account_copy['provider'] = provider
        account_copy['provider_display'] = provider_name(provider)
        paginated_accounts.append(account_copy)

    messages = []

    accounts_to_fetch = session.get('accounts', [])
    if just_created:
        # Prioritize immediate sidebar/account rendering after create.
        accounts_to_fetch = []
    if inbox_scope == 'active':
        active_account = next(
            (a for a in session.get('accounts', []) if isinstance(a, dict) and a.get('email') == active_email),
            None,
        )
        if not just_created:
            accounts_to_fetch = [active_account] if active_account else []

    # Show all messages from all accounts together, but keep the active account selected in the sidebar.
    for account in accounts_to_fetch:
        account_email = account['email']
        account_provider = normalize_provider(account.get('provider'))
        cache_key = account_cache_key(account_provider, account_email)
        cached_msgs = MESSAGE_CACHE.get(cache_key, [])

        mail = MailProvider(account_provider)

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
            parsed_dt = parse_message_datetime(created_at)
            formatted_date = parsed_dt.strftime('%b %d, %H:%M') if parsed_dt else created_at
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
            msg['account_provider'] = provider_name(account_provider)

            formatted_msgs.append(msg)

        # Cache messages per account for fallbacks
        if formatted_msgs:
            MESSAGE_CACHE[cache_key] = formatted_msgs
            messages.extend(formatted_msgs)
        else:
            messages.extend(cached_msgs)

    # Sort the combined inbox by date (most recent first)
    def _msg_date(m):
        parsed = parse_message_datetime(m.get('createdAt'))
        return parsed if parsed else datetime.datetime.min

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
        error=error,
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
        inbox_scope=inbox_scope,
    )

@app.route('/create_account_json', methods=['POST'])
def create_account_json():
    """AJAX endpoint for account creation. Returns JSON instead of redirecting."""
    session_id = request.sid if hasattr(request, 'sid') else str(id(session))
    current_time = time.time()
    last_creation_time = LAST_ACCOUNT_CREATION.get(session_id, 0)
    time_since_last_creation = current_time - last_creation_time

    if time_since_last_creation < ACCOUNT_CREATION_COOLDOWN:
        remaining_wait = ACCOUNT_CREATION_COOLDOWN - time_since_last_creation
        return jsonify({'success': False, 'error': f'Please wait {int(remaining_wait) + 1}s before creating another account.'}), 429

    selected_domain = request.form.get('domain', '')
    if '::' not in selected_domain:
        return jsonify({'success': False, 'error': 'Invalid domain selection.'}), 400

    provider_id, domain = selected_domain.split('::', 1)
    provider_id = normalize_provider(provider_id)

    username = request.form.get('username', '').strip()
    if not username:
        return jsonify({'success': False, 'error': 'Username is required.'}), 400

    password = secrets.token_urlsafe(12)
    email = f"{username}@{domain}"
    mail = MailProvider(provider_id)
    created, status_code, override = mail.create_account(email, password)

    if created and override:
        email = override.get('email', email)
        password = override.get('password', password)

    LAST_ACCOUNT_CREATION[session_id] = current_time

    if created:
        latest_accounts = load_accounts()
        exists_already = any(
            a.get('email') == email and normalize_provider(a.get('provider')) == provider_id
            for a in latest_accounts
        )
        if exists_already:
            session['active_email'] = email
            session.modified = True
            disp = f"{email[:20]}..." if len(email) > 20 else email
            return jsonify({'success': False, 'duplicate': True, 'error': f'Account {email} already exists.', 'email': email, 'display_email': disp, 'provider': provider_id, 'provider_display': provider_name(provider_id)}), 409

        latest_accounts.append({'email': email, 'password': password, 'provider': provider_id})
        session_accounts = session.get('accounts', [])
        session['accounts'] = merge_account_lists(latest_accounts, session_accounts)
        session['active_email'] = email
        session.modified = True

        global PERSISTENT_ACCOUNTS
        PERSISTENT_ACCOUNTS = merge_account_lists(
            [{'email': email, 'password': password, 'provider': provider_id}],
            PERSISTENT_ACCOUNTS,
        )
        save_account(email, password, provider_id)

        disp = f"{email[:20]}..." if len(email) > 20 else email
        return jsonify({'success': True, 'email': email, 'display_email': disp, 'provider': provider_id, 'provider_display': provider_name(provider_id)})
    elif status_code == 400:
        error_msg = 'Invalid email address or account already exists. Please try a different username.'
    elif status_code == 422:
        error_msg = 'Unprocessable entity. Check the email format.'
    elif status_code == 429:
        error_msg = 'Rate limited by email service. Please wait a few seconds and try again.'
    elif status_code >= 500:
        error_msg = 'Server error. Please try again later.'
    else:
        error_msg = f'Failed to create account (Status: {status_code}). Please try again.'

    return jsonify({'success': False, 'error': error_msg}), 400


@app.route('/create_account', methods=['POST'])
def create_account():
    # Rate limiting check: prevent spamming account creation
    session_id = request.sid if hasattr(request, 'sid') else str(id(session))
    current_time = time.time()
    last_creation_time = LAST_ACCOUNT_CREATION.get(session_id, 0)
    time_since_last_creation = current_time - last_creation_time
    
    if time_since_last_creation < ACCOUNT_CREATION_COOLDOWN:
        remaining_wait = ACCOUNT_CREATION_COOLDOWN - time_since_last_creation
        error_msg = f"Please wait {int(remaining_wait) + 1} seconds before creating another account. This helps prevent rate limiting."
        domains = get_combined_domains()
        return render_template('index.html', domains=domains, error=error_msg, accounts=session.get('accounts', []), active_email=session.get('active_email'))

    selected_domain = request.form.get('domain', '')
    if '::' not in selected_domain:
        domains = get_combined_domains()
        return render_template('index.html', domains=domains, error='Invalid domain selection.', accounts=session.get('accounts', []), active_email=session.get('active_email'))

    provider_id, domain = selected_domain.split('::', 1)
    provider_id = normalize_provider(provider_id)

    username = request.form.get('username', '').strip()
    password = secrets.token_urlsafe(12)
    email = f"{username}@{domain}"
    mail = MailProvider(provider_id)
    created, status_code, override = mail.create_account(email, password)

    # Some providers may return a normalized account payload.
    if created and override:
        email = override.get('email', email)
        password = override.get('password', password)

    # Record the creation attempt timestamp
    LAST_ACCOUNT_CREATION[session_id] = current_time

    if created:
        # Merge with latest shared state to avoid overwriting accounts from other users/devices.
        latest_accounts = load_accounts()
        exists_already = any(
            a.get('email') == email and normalize_provider(a.get('provider')) == provider_id
            for a in latest_accounts
        )
        if not exists_already:
            latest_accounts.append({'email': email, 'password': password, 'provider': provider_id})
        else:
            session['active_email'] = email
            session.modified = True
            return redirect(
                url_for(
                    'index',
                    active=email,
                    scope='active',
                    exists=1,
                )
            )

        session_accounts = session.get('accounts', [])
        session['accounts'] = merge_account_lists(latest_accounts, session_accounts)
        session['active_email'] = email
        session.modified = True

        # Persist accounts across server restarts
        global PERSISTENT_ACCOUNTS
        PERSISTENT_ACCOUNTS = merge_account_lists(
            [{'email': email, 'password': password, 'provider': provider_id}],
            PERSISTENT_ACCOUNTS,
        )
        save_account(email, password, provider_id)

        return redirect(url_for('index', created=1))
    elif status_code == 400:
        error_msg = "Invalid email address or account already exists. Please try a different username."
    elif status_code == 422:
        error_msg = "Unprocessable entity. Check the email format."
    elif status_code == 429:
        error_msg = "Rate limited by email service. Please wait a few seconds and try again. (HTTP 429)"
    elif status_code >= 500:
        error_msg = "Server error. Please try again later."
    else:
        error_msg = f"Failed to create account (Status: {status_code}). Please try again."

    domains = get_combined_domains()
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

    provider_id = normalize_provider(active_account.get('provider'))
    cache_key = account_cache_key(provider_id, active_email)
    mail = MailProvider(provider_id)
    token = mail.get_token(active_account['email'], active_account['password'])
    if not token:
        return redirect(url_for('index'))

    if action == 'delete':
        for mid in message_ids:
            mail.delete_message(token, mid)
            if cache_key in MESSAGE_CACHE:
                MESSAGE_CACHE[cache_key] = [m for m in MESSAGE_CACHE[cache_key] if m.get('id') != mid]

    return redirect(url_for('index'))

@app.route('/message/<message_id>')
def view_message(message_id):
    active_email = session.get('active_email')
    if not active_email:
        return redirect(url_for('index'))

    active_account = next((a for a in session.get('accounts', []) if a['email'] == active_email), None)
    if not active_account:
        return redirect(url_for('index'))

    provider_id = normalize_provider(active_account.get('provider'))
    cache_key = account_cache_key(provider_id, active_email)
    mail = MailProvider(provider_id)
    token = mail.get_token(active_account['email'], active_account['password'])
    if not token:
        return redirect(url_for('index'))

    message = mail.get_message(token, message_id)
    if not message:
        # Fall back to cached messages if the API can't return the message (e.g., rate limit)
        message = next((m for m in MESSAGE_CACHE.get(cache_key, []) if m.get('id') == message_id), None)

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