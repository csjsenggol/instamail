import datetime
import ast
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

def get_domain_label(domain_obj):
    """Safely extract domain label, handling both clean dicts and stringified representations."""
    def parse_dictish(value):
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            raw_value = value.strip()
            if raw_value.startswith('{') and raw_value.endswith('}'):
                try:
                    parsed = ast.literal_eval(raw_value)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    return None
        return None

    payload = parse_dictish(domain_obj)
    if payload:
        # Handle nested dirty payloads where label/domain itself is another dict string.
        nested = parse_dictish(payload.get('label')) or parse_dictish(payload.get('domain'))
        if nested:
            payload = nested

        label = payload.get('label')
        if isinstance(label, str):
            clean_label = label.strip()
            if clean_label and not clean_label.startswith('{'):
                return clean_label

        domain = payload.get('domain')
        if isinstance(domain, str):
            clean_domain = domain.strip()
            if clean_domain:
                return clean_domain

        value = payload.get('value')
        if isinstance(value, str):
            clean_value = value.strip()
            if '::' in clean_value:
                return clean_value.split('::', 1)[1].strip()
            if clean_value and not clean_value.startswith('{'):
                return clean_value

    raw = str(domain_obj).strip()
    domain_match = re.search(r"([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)", raw)
    if domain_match:
        return domain_match.group(1)
    return raw

def get_domain_value(domain_obj):
    """Safely extract domain value (provider::domain), handling both clean dicts and stringified representations."""
    def parse_dictish(value):
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            raw_value = value.strip()
            if raw_value.startswith('{') and raw_value.endswith('}'):
                try:
                    parsed = ast.literal_eval(raw_value)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    return None
        return None

    payload = parse_dictish(domain_obj)
    if payload:
        # Handle nested dirty payloads where value/domain is another dict string.
        nested = parse_dictish(payload.get('value')) or parse_dictish(payload.get('domain'))
        if nested:
            payload = nested

        value = payload.get('value')
        if isinstance(value, str):
            clean_value = value.strip()
            if '::' in clean_value:
                return clean_value

        provider = payload.get('provider')
        domain = payload.get('domain')
        if isinstance(provider, str) and isinstance(domain, str):
            clean_provider = provider.strip()
            clean_domain = domain.strip()
            if clean_provider and clean_domain:
                return f"{clean_provider}::{clean_domain}"

    raw = str(domain_obj).strip()
    explicit_match = re.search(r"([a-zA-Z0-9_-]+)::([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)", raw)
    if explicit_match:
        return f"{explicit_match.group(1)}::{explicit_match.group(2)}"

    domain_match = re.search(r"([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)", raw)
    if domain_match:
        inferred_provider = 'mailinator' if 'mailinator' in raw.lower() else 'mailtm'
        return f"{inferred_provider}::{domain_match.group(1)}"

    return raw


def normalize_selected_domain(selected_domain):
    """Normalize submitted domain value to a provider::domain string."""
    if isinstance(selected_domain, dict):
        selected_domain = selected_domain.get('value', '')

    if isinstance(selected_domain, str):
        raw = selected_domain.strip()
        if raw.startswith('{') and raw.endswith('}'):
            try:
                parsed = ast.literal_eval(raw)
                if isinstance(parsed, dict):
                    value = parsed.get('value')
                    if isinstance(value, str):
                        return value.strip()
            except Exception:
                pass
        return raw

    return str(selected_domain or '').strip()


app.jinja_env.filters['domain_label'] = get_domain_label
app.jinja_env.filters['domain_value'] = get_domain_value

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


def delete_account(email, provider='mailtm'):
    """Delete one account from the DB by provider+email."""
    if not email:
        return
    try:
        with get_db_connection() as conn:
            conn.execute(
                "DELETE FROM accounts WHERE email = ? AND provider = ?",
                (email, normalize_provider(provider)),
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
        parsed = datetime.datetime.fromisoformat(text.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed.astimezone(datetime.timezone.utc)
    except Exception:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            parsed = datetime.datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            continue

    return None


def deleted_message_key(provider_id, email, message_id):
    return f"{normalize_provider(provider_id)}::{email}::{message_id}"


def parse_message_ref(value):
    """Parse checkbox payload: provider|email|message_id."""
    if not value or '|' not in value:
        return None, None, None
    provider_id, email, message_id = value.split('|', 2)
    provider_id = normalize_provider(provider_id.strip())
    email = email.strip()
    message_id = message_id.strip()
    if not email or not message_id:
        return None, None, None
    return provider_id, email, message_id

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
            raw = os.getenv('MAILINATOR_DOMAINS', 'mailinator.com').strip()

            def extract_domain(entry):
                if isinstance(entry, dict):
                    domain = entry.get('domain')
                    if isinstance(domain, str) and domain.strip():
                        return domain.strip()

                    value = entry.get('value')
                    if isinstance(value, str) and '::' in value:
                        return value.split('::', 1)[1].strip()
                    return None

                if isinstance(entry, str):
                    candidate = entry.strip().strip('"').strip("'")
                    if not candidate:
                        return None
                    if '::' in candidate:
                        return candidate.split('::', 1)[1].strip()
                    return candidate

                return None

            parsed_domains = []

            # Support env values like:
            # - mailinator.com,mailinator.us
            # - [{"domain": "mailinator.com"}]
            # - {"value": "mailinator::mailinator.com", "domain": "mailinator.com"}
            if raw.startswith('[') or raw.startswith('{'):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, list):
                        for item in parsed:
                            domain = extract_domain(item)
                            if domain:
                                parsed_domains.append(domain)
                    else:
                        domain = extract_domain(parsed)
                        if domain:
                            parsed_domains.append(domain)
                except Exception:
                    # Fall back to CSV parsing for malformed literals.
                    pass

            if not parsed_domains:
                for item in raw.split(','):
                    domain = extract_domain(item)
                    if domain:
                        parsed_domains.append(domain)

            seen = set()
            unique_domains = []
            for d in parsed_domains:
                if d not in seen:
                    seen.add(d)
                    unique_domains.append(d)

            return unique_domains or ['mailinator.com']

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
            # Production-safe normalization: some providers/deploys may return
            # dict objects instead of raw domain strings.
            if isinstance(domain, dict):
                domain = domain.get('domain') or domain.get('value') or domain.get('label')
                if isinstance(domain, str) and '::' in domain:
                    domain = domain.split('::', 1)[1]
            if not isinstance(domain, str):
                continue
            domain = domain.strip()
            if not domain:
                continue

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
    # Unified mode: always aggregate all accounts in one inbox view.
    inbox_scope = 'all'
    deleted_refs = set(session.get('deleted_message_refs', []))

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
            msg['account_provider_id'] = account_provider

            # Skip messages deleted by user locally (or not deletable remotely).
            ref_key = deleted_message_key(account_provider, account_email, msg.get('id'))
            if ref_key in deleted_refs:
                continue

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
        return parsed if parsed else datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

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

    selected_domain = normalize_selected_domain(request.form.get('domain', ''))
    if '::' not in selected_domain:
        return jsonify({'success': False, 'error': 'Invalid domain selection.'}), 400

    provider_id, domain = selected_domain.split('::', 1)
    provider_id = provider_id.strip()
    if provider_id not in MAIL_PROVIDERS:
        return jsonify({'success': False, 'error': 'Invalid provider selection. Refresh and choose a domain again.'}), 400

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

    selected_domain = normalize_selected_domain(request.form.get('domain', ''))
    if '::' not in selected_domain:
        domains = get_combined_domains(force_refresh=True)
        return render_template('index.html', domains=domains, error='Invalid domain selection.', accounts=session.get('accounts', []), active_email=session.get('active_email'))

    provider_id, domain = selected_domain.split('::', 1)
    provider_id = provider_id.strip()
    if provider_id not in MAIL_PROVIDERS:
        domains = get_combined_domains(force_refresh=True)
        return render_template('index.html', domains=domains, error='Invalid provider selection. Refresh and choose a domain again.', accounts=session.get('accounts', []), active_email=session.get('active_email'))

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
    message_refs = request.form.getlist('message_refs')
    if not message_refs:
        return redirect(url_for('index'))

    if action == 'delete':
        deleted_refs = set(session.get('deleted_message_refs', []))
        session_accounts = session.get('accounts', [])

        for ref in message_refs:
            provider_id, email, message_id = parse_message_ref(ref)
            if not provider_id or not email or not message_id:
                continue

            # Always hide deleted messages locally, including providers that don't support remote delete.
            deleted_refs.add(deleted_message_key(provider_id, email, message_id))

            account = next(
                (
                    a for a in session_accounts
                    if normalize_provider(a.get('provider')) == provider_id and a.get('email') == email
                ),
                None,
            )

            if account:
                token = MailProvider(provider_id).get_token(account['email'], account['password'])
                if token:
                    MailProvider(provider_id).delete_message(token, message_id)

            cache_key = account_cache_key(provider_id, email)
            if cache_key in MESSAGE_CACHE:
                MESSAGE_CACHE[cache_key] = [
                    m for m in MESSAGE_CACHE[cache_key]
                    if str(m.get('id')) != str(message_id)
                ]

        session['deleted_message_refs'] = list(deleted_refs)
        session.modified = True

    return redirect(url_for('index'))


@app.route('/accounts/remove', methods=['POST'])
def remove_account():
    """Remove an existing email account from sidebar and storage."""
    email = (request.form.get('email') or '').strip()
    provider_id = normalize_provider((request.form.get('provider') or '').strip())
    if not email:
        return redirect(url_for('index'))

    session_accounts = session.get('accounts', [])
    session['accounts'] = [
        a for a in session_accounts
        if not (
            a.get('email') == email and normalize_provider(a.get('provider')) == provider_id
        )
    ]

    global PERSISTENT_ACCOUNTS
    PERSISTENT_ACCOUNTS = [
        a for a in PERSISTENT_ACCOUNTS
        if not (
            a.get('email') == email and normalize_provider(a.get('provider')) == provider_id
        )
    ]

    # Keep active_email valid after removal.
    if session.get('active_email') == email:
        session['active_email'] = session['accounts'][0]['email'] if session.get('accounts') else None

    # Purge cached messages for removed account.
    cache_key = account_cache_key(provider_id, email)
    MESSAGE_CACHE.pop(cache_key, None)

    # Remove persisted DB row.
    delete_account(email, provider_id)

    session.modified = True
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


def log_startup_domains():
    """Print resolved domains at startup so deployments can be verified quickly."""
    try:
        domains = get_combined_domains(force_refresh=True)
        print(f"[startup] loaded domains: {len(domains)}")
        for item in domains:
            print(f"[startup] {item.get('provider')} -> {item.get('domain')}")
    except Exception as exc:
        print(f"[startup] failed to load domains: {exc}")

if __name__ == '__main__':
    if os.getenv('LOG_STARTUP_DOMAINS', '1') == '1':
        log_startup_domains()
    port = int(os.getenv('PORT', '5000'))
    debug = os.getenv('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)