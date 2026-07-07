#!/usr/bin/env python3
import hmac
import json
import os
import re
import stat
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


HOST = os.environ.get("IDENA_IMPORT_UI_HOST", "127.0.0.1")
PORT = int(os.environ.get("IDENA_IMPORT_UI_PORT", "9099"))
RPC_URL = os.environ.get("IDENA_RPC_URL", "http://127.0.0.1:9009")
API_KEY_FILE = Path(os.environ.get("IDENA_API_KEY_FILE", "/mnt/ssd/idena/idena-data/api.key"))
ACCESS_TOKEN = os.environ.get("IDENA_IMPORT_UI_TOKEN", "")
MAX_BODY_BYTES = 64 * 1024
MAX_API_KEY_BYTES = 512
MAX_RPC_URL_BYTES = 2048
MAX_RPC_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_IMPORT_KEY_CHARS = 16 * 1024
MAX_IMPORT_PASSWORD_CHARS = 1024
MIN_ACCESS_TOKEN_CHARS = 32
SAFE_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9._~:-]+$")
HTML_CSP = (
    "default-src 'self'; "
    "style-src 'self'; "
    "script-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)


INDEX_HTML = b"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>Idena Import</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body>
  <main>
    <header>
      <h1>Import Idena address on the Pi</h1>
      <p>Local-only UI. Calls the Pi idena-go RPC method dna_importKey, the same import path used by IdenaAI.</p>
    </header>
    <section>
      <div class="status" id="status">Checking local Pi RPC...</div>
      <form id="form" autocomplete="off">
        <label for="key">Encrypted private key</label>
        <textarea id="key" spellcheck="false" autocomplete="off" required></textarea>
        <label for="password">Password</label>
        <input id="password" type="password" autocomplete="current-password" required>
        <button id="submit" type="submit">Import into Pi node</button>
        <button class="secondary" id="show" type="button">Show password</button>
      </form>
      <div id="result" class="result"></div>
      <p class="fine">Do not paste your key or password into chat. Type it here only if you trust this Mac and the Pi.</p>
    </section>
  </main>
  <script src="/app.js" defer></script>
</body>
</html>"""

APP_CSS = b""":root { color-scheme: light; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
body { margin: 0; min-height: 100vh; background: #f5f7f4; color: #10231d; display: grid; place-items: center; }
main { width: min(760px, calc(100vw - 32px)); background: #fff; border: 1px solid #dde5df; border-radius: 10px; box-shadow: 0 18px 60px rgba(16,35,29,.10); overflow: hidden; }
header { padding: 28px 30px; background: #0b241d; color: #f7fbf7; }
h1 { margin: 0 0 8px; font-size: 28px; line-height: 1.15; }
p { margin: 0; color: #63706b; line-height: 1.45; }
header p { color: #b8c7c0; }
section { padding: 26px 30px; }
label { display: block; font-weight: 700; font-size: 13px; margin: 18px 0 8px; color: #2f3d38; }
textarea, input { width: 100%; box-sizing: border-box; border: 1px solid #ccd8d1; border-radius: 8px; padding: 12px 14px; font: inherit; background: #fbfcfb; color: #10231d; }
textarea { min-height: 120px; resize: vertical; }
button { margin-top: 20px; border: 0; border-radius: 8px; padding: 12px 18px; font-weight: 800; font: inherit; cursor: pointer; background: #ff9f1a; color: #10231d; }
button.secondary { margin-left: 10px; background: #e8eeeb; }
button:disabled { opacity: .55; cursor: not-allowed; }
.status { display: grid; gap: 8px; padding: 16px; background: #f7faf8; border: 1px solid #dde5df; border-radius: 8px; font-size: 14px; }
.ok { color: #167c5c; font-weight: 800; }
.warn { color: #a16000; font-weight: 800; }
.err { color: #a72b2b; font-weight: 800; }
.result { margin-top: 18px; padding: 14px 16px; border-radius: 8px; display: none; }
.result.show { display: block; }
.result.ok { background: #ebf8f1; border: 1px solid #b7e3cc; }
.result.err { background: #fff1f1; border: 1px solid #efb8b8; }
.fine { margin-top: 12px; font-size: 13px; color: #63706b; }
"""

APP_JS = b"""function readAccessToken() {
  const fragment = new URLSearchParams(location.hash.replace(/^#/, ''));
  const value = fragment.get('token') || '';
  if (window.history && window.history.replaceState) {
    window.history.replaceState(null, document.title, location.pathname);
  }
  return value;
}

const token = readAccessToken();
const statusEl = document.getElementById('status');
const resultEl = document.getElementById('result');
const form = document.getElementById('form');
const keyEl = document.getElementById('key');
const passwordEl = document.getElementById('password');
const submitEl = document.getElementById('submit');
const showEl = document.getElementById('show');

function textRow(text, className = '') {
  const row = document.createElement('div');
  if (className) {
    row.className = className;
  }
  row.textContent = text;
  return row;
}

function statusError(text) {
  const row = document.createElement('span');
  row.className = 'err';
  row.textContent = text;
  statusEl.replaceChildren(row);
}

function setResult(kind, text) {
  resultEl.className = `result show ${kind}`;
  resultEl.textContent = text;
}

async function api(path, options = {}) {
  const headers = {'X-Import-Token': token, ...(options.headers || {})};
  const res = await fetch(path, {...options, headers, cache: 'no-store'});
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function refreshStatus() {
  if (!token) {
    statusError('Missing access token.');
    submitEl.disabled = true;
    return;
  }
  try {
    const data = await api('/api/status');
    const sync = data.syncing || {};
    const coinbase = data.coinbase || 'not loaded';
    statusEl.replaceChildren(
      textRow(sync.syncing ? 'Syncing' : 'Synced or caught up', sync.syncing ? 'warn' : 'ok'),
      textRow(`Height ${sync.currentBlock || '-'} / ${sync.highestBlock || '-'}`),
      textRow(`Current coinbase: ${coinbase}`),
    );
  } catch (err) {
    statusError(err.message);
  }
}

showEl.addEventListener('click', () => {
  passwordEl.type = passwordEl.type === 'password' ? 'text' : 'password';
  showEl.textContent = passwordEl.type === 'password' ? 'Show password' : 'Hide password';
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  resultEl.className = 'result';
  submitEl.disabled = true;
  try {
    const data = await api('/api/import', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({key: keyEl.value.trim(), password: passwordEl.value})
    });
    keyEl.value = '';
    passwordEl.value = '';
    setResult('ok', data.message || 'Imported. Restart idena.service if the node does not switch address within a minute.');
    await refreshStatus();
  } catch (err) {
    setResult('err', err.message);
  } finally {
    submitEl.disabled = false;
  }
});

refreshStatus();
"""


def read_api_key():
    return validate_api_key_file(API_KEY_FILE)


def validate_loopback_rpc_url(value):
    if not value or len(value) > MAX_RPC_URL_BYTES or any(ord(ch) < 32 for ch in value):
        raise ValueError("Idena RPC URL is empty, too long, or contains control characters")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Idena RPC URL scheme must be http or https")
    if not parsed.hostname:
        raise ValueError("Idena RPC URL must include a host")
    if parsed.username or parsed.password:
        raise ValueError("Idena RPC URL must not include userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("Idena RPC URL must not include query or fragment data")

    host = parsed.hostname
    try:
        loopback = ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if not loopback:
        raise ValueError("Idena RPC URL host must be loopback")
    return parsed


def validate_api_key_value(value):
    api_key = value.strip()
    if not api_key or len(api_key) > MAX_API_KEY_BYTES:
        raise ValueError(f"Idena API key must be 1-{MAX_API_KEY_BYTES} bytes")
    if any(ord(ch) < 32 for ch in api_key):
        raise ValueError("Idena API key must not contain control characters")
    return api_key


def validate_api_key_file(path):
    validate_secret_parent(path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"failed to inspect Idena API key file {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Idena API key file must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Idena API key path must be a regular file: {path}")
    if os.name == "posix" and metadata.st_mode & 0o077:
        raise ValueError(f"Idena API key file is too permissive; run chmod 600 {path}")
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_API_KEY_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"failed to read Idena API key file {path}: {exc}") from exc
    if len(raw) > MAX_API_KEY_BYTES:
        raise ValueError(f"Idena API key must be 1-{MAX_API_KEY_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Idena API key file must be valid UTF-8") from exc
    return validate_api_key_value(text)


def validate_secret_parent(path):
    parent = path.parent if str(path.parent) else Path(".")
    reject_symlink_ancestors(parent)
    try:
        metadata = parent.lstat()
    except OSError as exc:
        raise ValueError(f"failed to inspect Idena API key parent directory {parent}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Idena API key parent directory must not be a symlink: {parent}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"Idena API key parent path must be a directory: {parent}")
    if os.name == "posix" and metadata.st_mode & 0o022:
        raise ValueError(
            f"Idena API key parent directory is group/world writable; use chmod go-w {parent}"
        )


def reject_symlink_ancestors(path):
    original = Path(path)
    probe = original if original.is_absolute() else Path.cwd() / original
    parts = probe.parts
    if not parts:
        return
    current_path = Path(parts[0])
    for part in parts[1:]:
        current_path = current_path / part
        try:
            metadata = current_path.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            try:
                parent_metadata = current_path.parent.lstat()
            except OSError as exc:
                raise ValueError(
                    f"failed to inspect Idena API key symlink parent {current_path.parent}: {exc}"
                ) from exc
            if metadata.st_uid != 0 or parent_metadata.st_mode & 0o022:
                raise ValueError(
                    f"Idena API key path contains unsafe symlinked ancestor: {current_path}"
                )


def rpc_call(method, params=None, timeout=15):
    validate_loopback_rpc_url(RPC_URL)
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or [],
            "key": read_api_key(),
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        RPC_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return parse_rpc_response(response.read(MAX_RPC_RESPONSE_BYTES + 1))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Idena RPC unavailable: {exc}") from exc


def parse_rpc_response(data):
    if len(data) > MAX_RPC_RESPONSE_BYTES:
        raise RuntimeError("Idena RPC response is too large")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Idena RPC response is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Idena RPC response must be a JSON object")
    return payload


def json_response(handler, status, payload):
    data = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Cross-Origin-Opener-Policy", "same-origin")
    handler.send_header("Cross-Origin-Resource-Policy", "same-origin")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def static_response(handler, content_type, body):
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Cross-Origin-Opener-Policy", "same-origin")
    handler.send_header("Cross-Origin-Resource-Policy", "same-origin")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def authorized(handler):
    token_headers = handler.headers.get_all("X-Import-Token") or []
    if len(token_headers) != 1:
        return False
    supplied = token_headers[0]
    if len(supplied) > MAX_API_KEY_BYTES or not SAFE_TOKEN_PATTERN.match(supplied):
        return False
    return bool(ACCESS_TOKEN) and hmac.compare_digest(supplied, ACCESS_TOKEN)


def request_path(raw_path):
    return urlparse(raw_path).path


def request_has_query_token(raw_path):
    return any(
        name.lower() == "token"
        for name, _value in parse_qsl(urlparse(raw_path).query, keep_blank_values=True)
    )


def request_content_length(headers):
    length_headers = headers.get_all("Content-Length") or []
    if len(length_headers) != 1:
        raise ValueError("exactly one Content-Length header is required")
    try:
        length = int(length_headers[0])
    except ValueError as exc:
        raise ValueError("Content-Length must be an integer") from exc
    if length <= 0 or length > MAX_BODY_BYTES:
        raise ValueError("invalid request size")
    return length


def parse_import_payload(raw_body):
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("request body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")

    key = payload.get("key")
    password = payload.get("password")
    if not isinstance(key, str) or not isinstance(password, str):
        raise ValueError("key and password must be strings")

    if any(ord(ch) < 32 for ch in key) or any(ord(ch) < 32 for ch in password):
        raise ValueError("key and password must not contain control characters")
    key = key.strip()
    if not key or not password:
        raise ValueError("key and password are required")
    if len(key) > MAX_IMPORT_KEY_CHARS:
        raise ValueError("key is too large")
    if len(password) > MAX_IMPORT_PASSWORD_CHARS:
        raise ValueError("password is too large")

    return key, password


def validate_startup_config():
    if not ACCESS_TOKEN:
        raise SystemExit("IDENA_IMPORT_UI_TOKEN is required")
    if (
        len(ACCESS_TOKEN) < MIN_ACCESS_TOKEN_CHARS
        or len(ACCESS_TOKEN) > MAX_API_KEY_BYTES
        or not SAFE_TOKEN_PATTERN.match(ACCESS_TOKEN)
    ):
        raise SystemExit("IDENA_IMPORT_UI_TOKEN must be a strong URL-safe token")
    try:
        validate_loopback_rpc_url(RPC_URL)
        validate_api_key_file(API_KEY_FILE)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    try:
        host_ip = ip_address(HOST)
        loopback = host_ip.is_loopback
    except ValueError:
        loopback = HOST.lower() == "localhost"

    if not loopback:
        raise SystemExit("Refusing to bind Idena import UI to a non-loopback host")


class Handler(BaseHTTPRequestHandler):
    server_version = "PoHWIdenaImportUI/1"

    def log_message(self, _format, *_args):
        return

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def do_GET(self):
        if request_has_query_token(self.path):
            json_response(self, 400, {"error": "use #token=... instead of ?token=..."})
            return
        path = request_path(self.path)
        if path == "/api/status":
            if not authorized(self):
                json_response(self, 403, {"error": "unauthorized"})
                return
            try:
                syncing = rpc_call("bcn_syncing", timeout=6).get("result")
                coinbase_resp = rpc_call("dna_getCoinbaseAddr", timeout=6)
                json_response(
                    self,
                    200,
                    {
                        "syncing": syncing,
                        "coinbase": coinbase_resp.get("result"),
                    },
                )
            except Exception as exc:
                json_response(self, 502, {"error": str(exc)})
            return

        if path != "/":
            if path == "/app.css":
                static_response(self, "text/css; charset=utf-8", APP_CSS)
                return
            if path == "/app.js":
                static_response(self, "application/javascript; charset=utf-8", APP_JS)
                return
            json_response(self, 404, {"error": "not found"})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Security-Policy", HTML_CSP)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Length", str(len(INDEX_HTML)))
        self.end_headers()
        self.wfile.write(INDEX_HTML)

    def do_POST(self):
        if request_path(self.path) != "/api/import":
            json_response(self, 404, {"error": "not found"})
            return
        if not authorized(self):
            json_response(self, 403, {"error": "unauthorized"})
            return

        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            json_response(self, 415, {"error": "Content-Type must be application/json"})
            return

        try:
            length = request_content_length(self.headers)
        except ValueError as exc:
            json_response(self, 413, {"error": str(exc)})
            return

        try:
            try:
                key, password = parse_import_payload(self.rfile.read(length))
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
                return

            response = rpc_call("dna_importKey", [{"key": key, "password": password}], timeout=30)
            if response.get("error"):
                message = response["error"].get("message") or "dna_importKey failed"
                json_response(self, 400, {"error": message})
                return

            json_response(
                self,
                200,
                {
                    "ok": True,
                    "message": "Imported into the Pi node. If the address does not appear, restart idena.service.",
                },
            )
        except Exception as exc:
            json_response(self, 500, {"error": str(exc)})


class ImportUiServer(ThreadingHTTPServer):
    daemon_threads = True


def main():
    validate_startup_config()
    server = ImportUiServer((HOST, PORT), Handler)
    print(f"Serving local Idena import UI on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
