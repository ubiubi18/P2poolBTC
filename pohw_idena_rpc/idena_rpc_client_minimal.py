import json
import http.client
import os
import stat
import typing
import urllib.request
import urllib.error

Json = typing.Union[dict, list, str, int, float, bool, None]
MAX_IDENA_API_KEY_BYTES = 512
MAX_IDENA_RPC_RESPONSE_BYTES = 64 * 1024 * 1024


class IdenaRPCError(Exception):
    """Raised when the Idena node returns an error or cannot be reached."""


class IdenaRPCClientMinimal:
    """
    Minimal JSON-RPC client for Idena using only Python standard library.

    - Uses urllib for HTTP POST.
    - Reads IDENA_RPC_URL and IDENA_API_KEY_FILE from environment variables.
    - Does not depend on any third party packages.
    """

    def __init__(
        self,
        url: typing.Optional[str] = None,
        api_key: typing.Optional[str] = None,
        api_key_file: typing.Optional[str] = None,
        timeout: int = 10,
    ) -> None:
        self.url = url or os.getenv("IDENA_RPC_URL", "http://localhost:9009")
        api_key_file = api_key_file or os.getenv("IDENA_API_KEY_FILE", "")
        if api_key:
            self.api_key = _validate_api_key(api_key)
        elif api_key_file:
            self.api_key = read_protected_secret_file(api_key_file)
        else:
            self.api_key = ""

        if not self.api_key:
            raise RuntimeError(
                "IDENA_API_KEY_FILE or api_key argument is not set. Configure a protected API key file."
            )

        self.timeout = timeout

    def _rpc_payload(
        self,
        method: str,
        params: typing.Optional[typing.List[Json]] = None,
        request_id: int = 1,
    ) -> bytes:
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "key": self.api_key,  # Idena expects the api key in the JSON body
            "method": method,
            "params": params or [],
        }
        return json.dumps(payload).encode("utf-8")

    def call(
        self,
        method: str,
        params: typing.Optional[typing.List[Json]] = None,
        request_id: int = 1,
    ) -> Json:
        """
        Low level JSON-RPC call.

        Raises IdenaRPCError on HTTP errors or JSON-RPC errors.
        Returns the 'result' field on success.
        """
        data = self._rpc_payload(method, params=params, request_id=request_id)
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.getcode()
                body = read_limited_rpc_response_body(resp, "Idena RPC")
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            http.client.HTTPException,
        ) as e:
            raise IdenaRPCError(f"HTTP error talking to Idena RPC: {e}") from e

        if status != 200:
            raise IdenaRPCError(
                f"Non 200 HTTP status from Idena RPC: {status} - {body}"
            )

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as e:
            raise IdenaRPCError(f"Invalid JSON response from Idena RPC: {body}") from e

        if "error" in payload and payload["error"] is not None:
            raise IdenaRPCError(f"Idena RPC error: {payload['error']}")

        if "result" not in payload:
            raise IdenaRPCError(f"Missing 'result' in Idena RPC response: {payload}")

        return payload["result"]

    # ------------- Convenience helpers -------------

    def get_coinbase_addr(self) -> str:
        result = self.call("dna_getCoinbaseAddr")
        return str(result)

    def get_epoch(self) -> dict:
        result = self.call("dna_epoch")
        if not isinstance(result, dict):
            raise IdenaRPCError(f"Unexpected result type for dna_epoch: {type(result)}")
        return result

    def get_identity(self, address: str) -> dict:
        result = self.call("dna_identity", [address])
        if not isinstance(result, dict):
            raise IdenaRPCError(
                f"Unexpected result type for dna_identity: {type(result)}"
            )
        return result

    def get_last_block(self) -> dict:
        result = self.call("bcn_lastBlock")
        if not isinstance(result, dict):
            raise IdenaRPCError(
                f"Unexpected result type for bcn_lastBlock: {type(result)}"
            )
        return result

    def get_block_at_height(self, height: int) -> dict:
        result = self.call("bcn_blockAt", [height])
        if not isinstance(result, dict):
            raise IdenaRPCError(
                f"Unexpected result type for bcn_blockAt: {type(result)}"
            )
        return result

    def get_identity_root_at_height(self, height: int) -> str:
        block = self.get_block_at_height(height)
        header = block.get("header", {})
        identity_root = header.get("identityRoot") or block.get("identityRoot")
        if not identity_root:
            raise IdenaRPCError(
                f"identityRoot not found in block at height {height}. "
                f"Raw block: {json.dumps(block)}"
            )
        return str(identity_root)

    def get_current_identity_root(self) -> str:
        last_block = self.get_last_block()
        header = last_block.get("header", {})
        identity_root = header.get("identityRoot") or last_block.get("identityRoot")
        if not identity_root:
            raise IdenaRPCError(
                f"identityRoot not found in last block. "
                f"Raw block: {json.dumps(last_block)}"
            )
        return str(identity_root)


def read_protected_secret_file(path: str) -> str:
    if os.path.islink(path):
        raise RuntimeError(f"Idena API key file must not be a symlink: {path}")
    try:
        file_stat = os.stat(path)
    except OSError as exc:
        raise RuntimeError(f"Idena API key file is not readable: {path}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise RuntimeError(f"Idena API key file must be a regular file: {path}")
    if file_stat.st_mode & 0o077:
        raise RuntimeError(f"Idena API key file is too permissive; run chmod 600 {path}")

    parent = os.path.dirname(os.path.abspath(path)) or "."
    try:
        parent_stat = os.lstat(parent)
    except OSError as exc:
        raise RuntimeError(f"Idena API key parent directory is not readable: {parent}") from exc
    if stat.S_ISLNK(parent_stat.st_mode):
        raise RuntimeError(f"Idena API key parent directory must not be a symlink: {parent}")
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise RuntimeError(f"Idena API key parent must be a directory: {parent}")
    if parent_stat.st_mode & 0o022:
        raise RuntimeError(
            f"Idena API key parent directory is group/world writable: {parent}"
        )
    _reject_unsafe_symlink_ancestors(parent, "Idena API key parent")

    with open(path, "rb") as handle:
        raw = handle.read(MAX_IDENA_API_KEY_BYTES + 1)
    if len(raw) > MAX_IDENA_API_KEY_BYTES:
        raise RuntimeError(
            f"Idena API key must be 1-{MAX_IDENA_API_KEY_BYTES} bytes"
        )
    return _validate_api_key(raw.decode("utf-8", errors="strict").rstrip("\r\n"))


def _reject_unsafe_symlink_ancestors(path: str, label: str) -> None:
    current = os.path.abspath(path)
    while current and current != os.path.dirname(current):
        if os.path.islink(current):
            try:
                link_stat = os.lstat(current)
                parent_stat = os.lstat(os.path.dirname(current) or os.sep)
            except OSError as exc:
                raise RuntimeError(f"{label} symlink ancestor is not inspectable: {current}") from exc
            if link_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
                raise RuntimeError(f"{label} contains unsafe symlink ancestor: {current}")
        current = os.path.dirname(current)


def read_limited_rpc_response_body(resp: typing.Any, label: str) -> str:
    content_length = _response_content_length(resp)
    if content_length is not None and content_length > MAX_IDENA_RPC_RESPONSE_BYTES:
        raise IdenaRPCError(
            f"{label} response is too large: {content_length} bytes exceeds "
            f"{MAX_IDENA_RPC_RESPONSE_BYTES}"
        )
    raw = resp.read(MAX_IDENA_RPC_RESPONSE_BYTES + 1)
    if len(raw) > MAX_IDENA_RPC_RESPONSE_BYTES:
        raise IdenaRPCError(
            f"{label} response is too large: exceeds {MAX_IDENA_RPC_RESPONSE_BYTES} bytes"
        )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IdenaRPCError(f"{label} response is not valid UTF-8") from exc


def _response_content_length(resp: typing.Any) -> typing.Optional[int]:
    raw_length = None
    getheader = getattr(resp, "getheader", None)
    if callable(getheader):
        raw_length = getheader("Content-Length")
    elif hasattr(resp, "headers"):
        raw_length = resp.headers.get("Content-Length")
    if raw_length in (None, ""):
        return None
    try:
        length = int(raw_length)
    except (TypeError, ValueError) as exc:
        raise IdenaRPCError(f"Idena RPC response has invalid Content-Length: {raw_length}") from exc
    if length < 0:
        raise IdenaRPCError(f"Idena RPC response has invalid Content-Length: {raw_length}")
    return length


def _validate_api_key(api_key: str) -> str:
    if not api_key or len(api_key) > MAX_IDENA_API_KEY_BYTES:
        return ""
    if any(ord(ch) < 32 for ch in api_key):
        raise RuntimeError("Idena API key must not contain control characters")
    return api_key
