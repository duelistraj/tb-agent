"""OAuth onboarding and rotating installation credentials for local profiles."""

from __future__ import annotations

import asyncio
import html
import secrets
import threading
import webbrowser
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from tether_agent import __version__
from tether_agent.config import ProfileConfig
from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.paths import ProfilePaths
from tether_agent.runtime import RuntimeRegistry
from tether_agent.state import CredentialRecord, StateStore

CALLBACK_TIMEOUT_SECONDS = 10 * 60
REFRESH_EARLY_SECONDS = 5 * 60
INSTALLATION_SCOPES = (
    "agent:register",
    "agent:config:read",
    "agent:claim",
    "agent:execute",
    "agent:heartbeat",
)


def _random_value() -> str:
    return secrets.token_urlsafe(48)


def pkce_pair() -> tuple[str, str]:
    verifier = _random_value()
    challenge = (
        urlsafe_b64encode(sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("OAuth issuer is not a valid server origin")
    if parsed.scheme == "http" and parsed.hostname not in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        raise RuntimeError("OAuth issuer must use HTTPS outside local development")
    port = parsed.port
    default_port = 443 if parsed.scheme == "https" else 80
    host = parsed.hostname.casefold()
    return f"{parsed.scheme}://{host}{f':{port}' if port not in {None, default_port} else ''}"


def _same_origin_url(value: str, origin: str, *, field: str) -> str:
    parsed = urlsplit(value)
    endpoint_origin = _origin(f"{parsed.scheme}://{parsed.netloc}")
    if (
        endpoint_origin != origin
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise RuntimeError(f"OAuth discovery returned an invalid {field}")
    return value


async def discover_oauth(server_url: str) -> dict[str, Any]:
    expected_origin = _origin(server_url)
    async with httpx.AsyncClient(
        base_url=server_url, timeout=15, follow_redirects=False
    ) as client:
        response = await client.get("/.well-known/oauth-authorization-server")
        response.raise_for_status()
    metadata = response.json()
    if _origin(str(metadata.get("issuer", ""))) != expected_origin:
        raise RuntimeError("OAuth issuer does not match the configured server")
    if "S256" not in metadata.get("code_challenge_methods_supported", []):
        raise RuntimeError("The server does not support S256 PKCE")
    for key in (
        "token_endpoint",
        "tether_agent_setup_endpoint",
        "tether_agent_setup_resume_endpoint",
        "tether_agent_credential_endpoint",
        "tether_agent_credential_activation_endpoint",
        "tether_agent_credential_refresh_endpoint",
        "tether_agent_installation_audience",
    ):
        metadata[key] = _same_origin_url(
            str(metadata.get(key, "")), expected_origin, field=key
        )
    client_id = metadata.get("tether_agent_native_client_id")
    if not isinstance(client_id, str) or not client_id:
        raise RuntimeError("The server does not advertise a native Tether Agent client")
    return metadata


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _CallbackServer

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path != "/callback":
            self.send_error(404)
            return
        if self.server.result is None:
            self.server.result = {
                key: values[-1]
                for key, values in parse_qs(
                    parsed.query, keep_blank_values=True
                ).items()
            }
            self.server.event.set()
        return_url = self.server.return_url
        if return_url:
            safe_url = html.escape(return_url, quote=True)
            body = (
                '<!doctype html><meta charset="utf-8">'
                f'<meta http-equiv="refresh" content="2;url={safe_url}">'
                "<title>Tether Agent authorization received</title>"
                "<h1>Authorization received</h1>"
                "<p>Tether Agent is securing the installation credentials. "
                "Returning to setup&hellip;</p>"
                f'<p><a href="{safe_url}">Return to setup</a></p>'
            ).encode()
        else:
            body = b"Tether Agent authorization received. You can close this window."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class _CallbackServer(ThreadingHTTPServer):
    result: dict[str, str] | None = None

    def __init__(self, port: int = 0, *, return_url: str | None = None) -> None:
        self.return_url = return_url
        super().__init__(("127.0.0.1", port), _CallbackHandler)
        self.event = threading.Event()

    @property
    def redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self.server_port}/callback"

    def wait(self) -> dict[str, str]:
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        try:
            if not self.event.wait(CALLBACK_TIMEOUT_SECONDS):
                raise RuntimeError("OAuth authorization timed out")
            assert self.result is not None
            return self.result
        finally:
            self.shutdown()
            thread.join(timeout=5)
            self.server_close()


def _capabilities(config: ProfileConfig, store: StateStore) -> dict[str, Any]:
    runtimes = RuntimeRegistry(
        store=store,
        sandbox=config.sandbox,
        settings=config.runtime_adapters,
    )
    return {
        "runtimes": runtimes.capabilities(),
        "sandbox": config.sandbox,
        "shell": True,
        "git": True,
        "network": config.allow_network,
        "writable_roots": [
            mapping.security_revision()
            for mapping in config.project_mappings
            if mapping.access == "write"
        ],
        "projects": [
            {
                "project_id": str(mapping.project_id),
                "access": mapping.access,
                "mapping_revision": mapping.security_revision(),
            }
            for mapping in config.project_mappings
        ],
    }


def _open_authorization(url: str) -> None:
    try:
        opened = webbrowser.open(url, new=1, autoraise=True)
    except webbrowser.Error:
        opened = False
    if not opened:
        print("Open this authorization URL in your browser:")
        print(url)


async def _exchange_and_complete(
    *,
    callback: dict[str, str],
    session: dict[str, str],
    store: StateStore,
) -> dict[str, Any]:
    if callback.get("state") != session["state_value"]:
        raise RuntimeError("OAuth callback state did not match")
    if callback.get("iss") != session["issuer"]:
        raise RuntimeError("OAuth callback issuer did not match")
    if callback.get("error"):
        raise RuntimeError("OAuth authorization was denied")
    code = callback.get("code")
    if not code:
        raise RuntimeError("OAuth callback did not include an authorization code")
    async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
        token_response = await client.post(
            session["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": session["client_id"],
                "redirect_uri": session["redirect_uri"],
                "code_verifier": session["code_verifier"],
            },
        )
        token_response.raise_for_status()
        setup_token = token_response.json()
        if setup_token.get("nonce") != session["nonce_value"]:
            raise RuntimeError("OAuth token nonce did not match")
        credential_response = await client.post(
            session["credential_endpoint"],
            headers={"Authorization": f"Bearer {setup_token['access_token']}"},
            json={"session_handle": session["session_handle"]},
        )
        credential_response.raise_for_status()
        result = credential_response.json()
        if result.get("audience") != session["audience"]:
            raise RuntimeError("Installation credential audience did not match")
        validate = await client.get(
            f"{session['issuer'].rstrip('/')}/api/agent/v1/credentials/status",
            headers={"Authorization": f"Bearer {result['access_token']}"},
        )
        validate.raise_for_status()
        validation = validate.json()
        if validation.get("audience") != session["audience"]:
            raise RuntimeError("Validated installation audience did not match")
        if validation.get("family_id") != result.get("family_id"):
            raise RuntimeError("Validated installation family did not match")
        if validation.get("activated"):
            raise RuntimeError("The replacement credential was activated prematurely")
    expires_at = datetime.now(UTC) + timedelta(seconds=int(result["expires_in"]))
    store.activate_installation_credential(
        access_token=str(result["access_token"]),
        refresh_token=str(result["refresh_token"]),
        expires_at=expires_at,
        generation=int(result["generation"]),
        oauth_client_id=session["client_id"],
        family_id=str(result["family_id"]),
    )
    store.record_registration(result["installation"])
    store.set_setting("authentication_required", "false")
    store.set_setting("credential_revoked", "false")
    store.set_setting("last_credential_type", "oauth_installation")
    store.clear_setup_session()
    async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
        activation = await client.post(
            session["activation_endpoint"],
            headers={"Authorization": f"Bearer {result['access_token']}"},
        )
        activation.raise_for_status()
    return result


async def _oauth_login_unlocked(
    *,
    paths: ProfilePaths,
    config: ProfileConfig,
    mode: str = "login",
    intent: str = "reauthorize",
    repository_hints: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    store = StateStore(paths.state_file)
    metadata = await discover_oauth(config.server_url)
    incomplete = store.setup_session()
    if (
        incomplete is not None
        and incomplete["mode"] == mode
        and incomplete["intent"] == intent
        and incomplete["issuer"] == metadata["issuer"]
        and datetime.fromisoformat(incomplete["expires_at"]) > datetime.now(UTC)
    ):
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            resume = await client.post(
                metadata["tether_agent_setup_resume_endpoint"],
                json={"session_handle": incomplete["session_handle"]},
            )
        if resume.status_code != 410:
            resume.raise_for_status()
            remote = resume.json()
            if remote.get("resumable"):
                if remote.get("authorization_url") != incomplete["authorization_url"]:
                    raise RuntimeError("Resumed setup authorization URL did not match")
                port = urlsplit(incomplete["redirect_uri"]).port
                assert port is not None
                callback_server = _CallbackServer(
                    port, return_url=incomplete["authorization_url"]
                )
                _open_authorization(incomplete["authorization_url"])
                callback = await asyncio.to_thread(callback_server.wait)
                return await _exchange_and_complete(
                    callback=callback, session=incomplete, store=store
                )
    if incomplete is not None:
        store.clear_setup_session()
    callback_server = _CallbackServer()
    verifier, challenge = pkce_pair()
    state_value = _random_value()
    nonce_value = _random_value()
    issuer = str(metadata["issuer"])
    proposal = {
        "client_id": metadata["tether_agent_native_client_id"],
        "expected_origin": _origin(config.server_url),
        "redirect_uri": callback_server.redirect_uri,
        "state": state_value,
        "nonce": nonce_value,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "installation_id": store.get_setting("installation_id"),
        "installation_name": config.installation_name,
        "protocol_version": config.protocol_version,
        "daemon_version": __version__,
        "mode": mode,
        "intent": intent,
        "projects": [
            {
                "project_id": str(mapping.project_id),
                "repository_url": mapping.remote_url,
                "access": mapping.access,
            }
            for mapping in config.project_mappings
        ],
        "repository_hints": repository_hints or [],
        "capabilities": _capabilities(config, store),
    }
    async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
        response = await client.post(
            metadata["tether_agent_setup_endpoint"], json=proposal
        )
        response.raise_for_status()
    created = response.json()
    callback_server.return_url = str(created["authorization_url"])
    local_session = {
        "session_handle": str(created["session_handle"]),
        "code_verifier": verifier,
        "state_value": state_value,
        "nonce_value": nonce_value,
        "redirect_uri": callback_server.redirect_uri,
        "issuer": issuer,
        "token_endpoint": str(metadata["token_endpoint"]),
        "credential_endpoint": str(metadata["tether_agent_credential_endpoint"]),
        "activation_endpoint": str(
            metadata["tether_agent_credential_activation_endpoint"]
        ),
        "audience": str(metadata["tether_agent_installation_audience"]),
        "authorization_url": str(created["authorization_url"]),
        "client_id": str(metadata["tether_agent_native_client_id"]),
        "expires_at": str(created["expires_at"]),
        "mode": mode,
        "intent": intent,
    }
    store.save_setup_session(local_session)
    _open_authorization(str(created["authorization_url"]))
    callback = await asyncio.to_thread(callback_server.wait)
    return await _exchange_and_complete(
        callback=callback, session=local_session, store=store
    )


async def oauth_login(
    *,
    paths: ProfilePaths,
    config: ProfileConfig,
    mode: str = "login",
    intent: str = "reauthorize",
    repository_hints: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    lock = ProfileLock(paths.credential_lock, label="OAuth credential change")
    try:
        lock.acquire()
    except LockUnavailable as error:
        raise RuntimeError(
            "Another process is changing this profile credential"
        ) from error
    try:
        return await _oauth_login_unlocked(
            paths=paths,
            config=config,
            mode=mode,
            intent=intent,
            repository_hints=repository_hints,
        )
    finally:
        lock.release()


async def validate_installation_credential(
    *, server_url: str, access_token: str
) -> dict[str, Any]:
    async with httpx.AsyncClient(base_url=server_url, timeout=20) as client:
        response = await client.get(
            "/api/agent/v1/credentials/status",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        return response.json()


async def refresh_credential(
    *,
    paths: ProfilePaths,
    server_url: str,
    force: bool = False,
) -> CredentialRecord:
    lock = ProfileLock(paths.credential_lock, label="credential refresh")
    try:
        lock.acquire()
    except LockUnavailable as error:
        raise RuntimeError("Another process is refreshing this profile") from error
    store = StateStore(paths.state_file)
    try:
        current = store.credential()
        if current is None:
            raise RuntimeError("No OAuth installation credential is configured")
        if current.revoked_at is not None or current.reauthentication_required:
            raise RuntimeError("OAuth reauthentication is required")
        if not force and current.access_expires_at > datetime.now(UTC) + timedelta(
            seconds=REFRESH_EARLY_SECONDS
        ):
            return current
        rotation_id = current.recovery_rotation_id or _random_value()
        current = store.prepare_credential_refresh(rotation_id)
        async with httpx.AsyncClient(base_url=server_url, timeout=30) as client:
            response: httpx.Response | None = None
            for attempt in range(3):
                try:
                    response = await client.post(
                        "/api/agent/v1/credentials/refresh",
                        json={
                            "refresh_token": current.refresh_token,
                            "client_id": current.oauth_client_id,
                            "rotation_id": rotation_id,
                        },
                    )
                    if response.status_code < 500:
                        break
                except httpx.TransportError:
                    if attempt == 2:
                        raise
                if attempt < 2:
                    await asyncio.sleep(2**attempt)
            assert response is not None
            if response.status_code in {401, 403}:
                store.require_reauthentication(revoked=True)
            response.raise_for_status()
            payload = response.json()
            store.finish_credential_refresh(
                expected_generation=current.generation,
                access_token=str(payload["access_token"]),
                refresh_token=str(payload["refresh_token"]),
                expires_at=datetime.now(UTC)
                + timedelta(seconds=int(payload["expires_in"])),
                generation=int(payload["generation"]),
            )
            refreshed = store.credential()
            assert refreshed is not None
            validation = await client.get(
                "/api/agent/v1/credentials/status",
                headers={"Authorization": f"Bearer {refreshed.access_token}"},
            )
            validation.raise_for_status()
        store.clear_credential_recovery()
        result = store.credential()
        assert result is not None
        return result
    finally:
        lock.release()
