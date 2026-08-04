import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Self

import httpx
import pytest

import tether_agent.oauth as oauth_module
from tether_agent.cli import build_parser, safe_error_message
from tether_agent.config import ProfileConfig
from tether_agent.oauth import (
    InstallationRevokedError,
    _exchange_and_complete,
    _oauth_login_unlocked,
    _origin,
    discover_oauth,
    pkce_pair,
    refresh_credential,
)
from tether_agent.paths import ProfilePaths
from tether_agent.state import StateStore


def test_pkce_uses_s256_and_high_entropy_verifier() -> None:
    verifier, challenge = pkce_pair()

    assert len(verifier) >= 43
    assert len(challenge) == 43
    assert verifier != challenge
    assert "=" not in challenge


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com",
        "https://user@example.com",
        "https://example.com/path",
        "https://example.com?token=value",
    ],
)
def test_oauth_origin_rejects_insecure_or_credentialed_servers(value: str) -> None:
    with pytest.raises(RuntimeError):
        _origin(value)


@pytest.mark.asyncio
async def test_oauth_discovery_validates_s256_and_same_origin_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/oauth-authorization-server"
        return httpx.Response(
            200,
            json={
                "issuer": "https://tetherbrain.net",
                "token_endpoint": "https://tetherbrain.net/oauth/token",
                "code_challenge_methods_supported": ["S256"],
                "tether_agent_native_client_id": "tether-agent-cli",
                "tether_agent_setup_endpoint": "https://tetherbrain.net/api/agent/v1/setup-sessions",
                "tether_agent_setup_resume_endpoint": "https://tetherbrain.net/api/agent/v1/setup-sessions/resume",
                "tether_agent_credential_endpoint": "https://tetherbrain.net/api/agent/v1/setup-sessions/complete",
                "tether_agent_credential_activation_endpoint": "https://tetherbrain.net/api/agent/v1/credentials/activate",
                "tether_agent_credential_refresh_endpoint": "https://tetherbrain.net/api/agent/v1/credentials/refresh",
                "tether_agent_installation_audience": "https://tetherbrain.net/api/agent/v1",
            },
        )

    def client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return original_client(*args, **kwargs)

    monkeypatch.setattr(oauth_module.httpx, "AsyncClient", client)

    metadata = await discover_oauth("https://tetherbrain.net")

    assert metadata["issuer"] == "https://tetherbrain.net"
    assert metadata["tether_agent_native_client_id"] == "tether-agent-cli"


def test_cli_exposes_phase_two_auth_commands_and_oauth_init_default() -> None:
    parser = build_parser()

    init = parser.parse_args(["init"])
    assert init.auth == "oauth"
    for command in ("login", "migrate", "refresh", "revoke"):
        parsed = parser.parse_args(["auth", command])
        assert parsed.auth_command == command


def test_loopback_callback_renders_secure_html_and_returns_to_setup() -> None:
    return_url = (
        "https://tetherbrain.net/agent/setup?session=setup-handle"
        "&step=repository_confirmation"
    )
    server = oauth_module._CallbackServer(return_url=return_url)
    wait_thread = threading.Thread(target=server.wait, daemon=True)
    wait_thread.start()

    try:
        response = httpx.get(
            server.redirect_uri,
            params={
                "code": "tb_sac_must-not-be-rendered",
                "iss": "https://tetherbrain.net",
                "state": "expected-state",
            },
            timeout=5,
        )
    finally:
        wait_thread.join(timeout=5)

    assert not wait_thread.is_alive()
    assert server.result == {
        "code": "tb_sac_must-not-be-rendered",
        "iss": "https://tetherbrain.net",
        "state": "expected-state",
    }
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    )
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "<!doctype html>" in response.text.casefold()
    assert "tb-agent authorization response received" in response.text
    assert (
        "https://tetherbrain.net/agent/setup?session=setup-handle"
        "&amp;step=repository_confirmation"
    ) in response.text
    assert "tb_sac_must-not-be-rendered" not in response.text


def test_loopback_callback_without_setup_url_renders_close_instructions() -> None:
    server = oauth_module._CallbackServer()
    wait_thread = threading.Thread(target=server.wait, daemon=True)
    wait_thread.start()

    try:
        response = httpx.get(
            server.redirect_uri,
            params={"error": "access_denied"},
            timeout=5,
        )
    finally:
        wait_thread.join(timeout=5)

    assert not wait_thread.is_alive()
    assert server.result == {"error": "access_denied"}
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert "You can close this window" in response.text
    assert "access_denied" not in response.text


@pytest.mark.asyncio
async def test_setup_proposal_and_resumable_state_preserve_workspace_add_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def discovery(server_url: str) -> dict[str, object]:
        assert server_url == "https://tetherbrain.net"
        return {
            "issuer": "https://tetherbrain.net",
            "token_endpoint": "https://tetherbrain.net/oauth/token",
            "tether_agent_native_client_id": "tb-agent-cli",
            "tether_agent_setup_endpoint": "https://tetherbrain.net/api/agent/setup",
            "tether_agent_setup_resume_endpoint": "https://tetherbrain.net/api/agent/setup/resume",
            "tether_agent_credential_endpoint": "https://tetherbrain.net/api/agent/setup/complete",
            "tether_agent_credential_activation_endpoint": "https://tetherbrain.net/api/agent/credentials/activate",
            "tether_agent_installation_audience": "https://tetherbrain.net/api/agent/v1",
        }

    class FakeCallbackServer:
        redirect_uri = "http://127.0.0.1:49152/callback"
        return_url = ""

        def wait(self) -> dict[str, str]:
            return {"code": "hidden"}

    class FakeClient:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *args: object) -> None:
            del args

        async def post(self, url: str, **kwargs: object) -> httpx.Response:
            captured["url"] = url
            captured["proposal"] = kwargs["json"]
            return httpx.Response(
                200,
                json={
                    "session_handle": "tb_ssh_hidden",
                    "authorization_url": "https://tetherbrain.net/setup/hidden",
                    "expires_at": "2099-01-01T00:00:00+00:00",
                },
                request=httpx.Request("POST", url),
            )

    async def complete(**kwargs: object) -> dict[str, object]:
        captured["local_session"] = kwargs["session"]
        return {"installation": {"status": "pending_approval"}}

    monkeypatch.setattr(oauth_module, "discover_oauth", discovery)
    monkeypatch.setattr(oauth_module, "_CallbackServer", FakeCallbackServer)
    monkeypatch.setattr(
        oauth_module.httpx, "AsyncClient", lambda **kwargs: FakeClient()
    )
    monkeypatch.setattr(oauth_module, "_open_authorization", lambda url: None)
    monkeypatch.setattr(oauth_module, "_exchange_and_complete", complete)
    paths = ProfilePaths(
        profile="team",
        config_dir=tmp_path / "config",
        state_dir=tmp_path / "state",
    )

    result = await _oauth_login_unlocked(
        paths=paths,
        config=ProfileConfig(server_url="https://tetherbrain.net"),
        intent="workspace_add",
        repository_hints=[
            {
                "repository_url": "ssh://git@github.com/TetherBrain/example",
                "access": "write",
            }
        ],
    )

    proposal = captured["proposal"]
    assert isinstance(proposal, dict)
    assert proposal["intent"] == "workspace_add"
    assert proposal["repository_hints"] == [
        {
            "repository_url": "ssh://git@github.com/TetherBrain/example",
            "access": "write",
        }
    ]
    assert "local_path" not in str(proposal)
    assert result["installation"] == {"status": "pending_approval"}
    setup = StateStore(paths.state_file).setup_session()
    assert setup is not None
    assert setup["intent"] == "workspace_add"


@pytest.mark.asyncio
async def test_replacement_proposal_never_rebinds_the_revoked_installation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    replaced_id = "11111111-1111-4111-8111-111111111111"

    async def discovery(server_url: str) -> dict[str, object]:
        del server_url
        return {
            "issuer": "https://tetherbrain.net",
            "token_endpoint": "https://tetherbrain.net/oauth/token",
            "tether_agent_native_client_id": "tb-agent-cli",
            "tether_agent_setup_endpoint": "https://tetherbrain.net/api/agent/setup",
            "tether_agent_setup_resume_endpoint": "https://tetherbrain.net/api/agent/setup/resume",
            "tether_agent_credential_endpoint": "https://tetherbrain.net/api/agent/setup/complete",
            "tether_agent_credential_activation_endpoint": "https://tetherbrain.net/api/agent/credentials/activate",
            "tether_agent_installation_audience": "https://tetherbrain.net/api/agent/v1",
            "tether_agent_setup_intents_supported": ["replace"],
        }

    class FakeCallbackServer:
        redirect_uri = "http://127.0.0.1:49152/callback"
        return_url = ""

        def wait(self) -> dict[str, str]:
            return {"code": "hidden"}

    class FakeClient:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *args: object) -> None:
            del args

        async def post(self, url: str, **kwargs: object) -> httpx.Response:
            captured["proposal"] = kwargs["json"]
            return httpx.Response(
                200,
                json={
                    "session_handle": "tb_ssh_hidden",
                    "authorization_url": "https://tetherbrain.net/setup/hidden",
                    "expires_at": "2099-01-01T00:00:00+00:00",
                },
                request=httpx.Request("POST", url),
            )

    async def complete(**kwargs: object) -> dict[str, object]:
        del kwargs
        return {"installation": {"status": "pending_approval"}}

    monkeypatch.setattr(oauth_module, "discover_oauth", discovery)
    monkeypatch.setattr(oauth_module, "_CallbackServer", FakeCallbackServer)
    monkeypatch.setattr(
        oauth_module.httpx, "AsyncClient", lambda **kwargs: FakeClient()
    )
    monkeypatch.setattr(oauth_module, "_open_authorization", lambda url: None)
    monkeypatch.setattr(oauth_module, "_exchange_and_complete", complete)
    paths = ProfilePaths("default", tmp_path / "config", tmp_path / "state")
    store = StateStore(paths.state_file)
    store.set_setting("installation_id", replaced_id)

    await _oauth_login_unlocked(
        paths=paths,
        config=ProfileConfig(server_url="https://tetherbrain.net"),
        intent="replace",
        replaces_installation_id=replaced_id,
        replacement_operation_id="22222222-2222-4222-8222-222222222222",
    )

    proposal = captured["proposal"]
    assert isinstance(proposal, dict)
    assert proposal["installation_id"] is None
    assert proposal["replaces_installation_id"] == replaced_id
    assert proposal["replacement_operation_id"] == (
        "22222222-2222-4222-8222-222222222222"
    )


def test_every_installation_secret_is_redacted() -> None:
    message = (
        "tb_iat_access-secret tb_irt_refresh-secret tb_sat_setup-secret "
        "tb_sac_code-secret tb_ssh_handle-secret tb_pat_fallback-secret"
    )

    redacted = safe_error_message(RuntimeError(message))

    assert "secret" not in redacted
    assert redacted.count("[REDACTED CREDENTIAL]") == 6


def test_credential_activation_is_atomic_and_does_not_remove_runtime_state(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.set_setting("installation_id", "installation-1")
    store.set_setting("agent_profile_id", "profile-1")
    store.set_setting("config_revision", "7")
    expires_at = datetime.now(UTC) + timedelta(minutes=15)

    store.activate_installation_credential(
        access_token="tb_iat_access",
        refresh_token="tb_irt_refresh",
        expires_at=expires_at,
        generation=3,
        oauth_client_id="tether-agent-cli",
        family_id="family-1",
    )

    credential = store.credential()
    assert credential is not None
    assert credential.generation == 3
    assert credential.access_token == "tb_iat_access"
    assert credential.refresh_token == "tb_irt_refresh"
    assert store.get_setting("installation_id") == "installation-1"
    assert store.get_setting("agent_profile_id") == "profile-1"
    assert store.configuration_revision() == 7


@pytest.mark.asyncio
async def test_activation_transport_failure_keeps_replacement_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.set_setting("installation_id", "old-installation")

    class FakeClient:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *args: object) -> None:
            del args

        async def post(self, url: str, **kwargs: object) -> httpx.Response:
            del kwargs
            if url.endswith("/oauth/token"):
                return httpx.Response(
                    200,
                    json={"access_token": "tb_sat_setup", "nonce": "nonce"},
                    request=httpx.Request("POST", url),
                )
            if url.endswith("/complete"):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "tb_iat_new",
                        "refresh_token": "tb_irt_new",
                        "expires_in": 900,
                        "generation": 1,
                        "family_id": "family-new",
                        "audience": "https://tetherbrain.net/api/agent/v1",
                        "installation": {
                            "id": "new-installation",
                            "status": "pending_approval",
                            "profiles": [],
                        },
                    },
                    request=httpx.Request("POST", url),
                )
            raise httpx.ConnectError(
                "activation interrupted", request=httpx.Request("POST", url)
            )

        async def get(self, url: str, **kwargs: object) -> httpx.Response:
            del kwargs
            return httpx.Response(
                200,
                json={
                    "audience": "https://tetherbrain.net/api/agent/v1",
                    "family_id": "family-new",
                    "activated": False,
                },
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr(
        oauth_module.httpx, "AsyncClient", lambda **kwargs: FakeClient()
    )
    result = await _exchange_and_complete(
        callback={
            "state": "state",
            "iss": "https://tetherbrain.net",
            "code": "tb_sac_code",
        },
        session={
            "state_value": "state",
            "issuer": "https://tetherbrain.net",
            "token_endpoint": "https://tetherbrain.net/oauth/token",
            "client_id": "tb-agent-cli",
            "redirect_uri": "http://127.0.0.1:49152/callback",
            "code_verifier": "v" * 43,
            "nonce_value": "nonce",
            "credential_endpoint": "https://tetherbrain.net/complete",
            "activation_endpoint": "https://tetherbrain.net/activate",
            "session_handle": "tb_ssh_session",
            "audience": "https://tetherbrain.net/api/agent/v1",
            "intent": "replace",
        },
        store=store,
    )

    assert result["installation"]["id"] == "new-installation"
    assert store.get_setting("installation_id") == "new-installation"
    assert store.get_setting("credential_activation_pending") == "true"
    assert store.credential() is not None


def test_refresh_recovery_survives_process_termination_before_persistence(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.activate_installation_credential(
        access_token="tb_iat_old",
        refresh_token="tb_irt_old",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
        generation=4,
        oauth_client_id="tether-agent-cli",
        family_id="family-1",
    )

    prepared = store.prepare_credential_refresh("rotation-recovery-value-1234567890")
    reopened = StateStore(store.path).credential()

    assert prepared.refresh_token == "tb_irt_old"
    assert reopened is not None
    assert reopened.generation == 4
    assert reopened.refresh_token == "tb_irt_old"
    assert reopened.previous_refresh_token == "tb_irt_old"
    assert reopened.recovery_rotation_id == "rotation-recovery-value-1234567890"


@pytest.mark.asyncio
async def test_refresh_distinguishes_a_revoked_installation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = ProfilePaths("default", tmp_path / "config", tmp_path / "state")
    store = StateStore(paths.state_file)
    store.activate_installation_credential(
        access_token="tb_iat_old",
        refresh_token="tb_irt_old",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
        generation=1,
        oauth_client_id="tb-agent-cli",
        family_id="family-old",
    )

    class FakeClient:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *args: object) -> None:
            del args

        async def post(self, url: str, **kwargs: object) -> httpx.Response:
            del kwargs
            return httpx.Response(
                401,
                json={
                    "detail": {
                        "code": "installation_revoked",
                        "message": "Installation was revoked",
                    }
                },
                request=httpx.Request("POST", url),
            )

    monkeypatch.setattr(
        oauth_module.httpx, "AsyncClient", lambda **kwargs: FakeClient()
    )

    with pytest.raises(InstallationRevokedError):
        await refresh_credential(
            paths=paths,
            server_url="https://tetherbrain.net",
            force=True,
        )

    assert store.get_setting("installation_revoked") == "true"
    credential = store.credential()
    assert credential is not None
    assert credential.reauthentication_required


def test_refresh_generation_compare_and_swap_preserves_valid_state_on_fault(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.activate_installation_credential(
        access_token="tb_iat_current",
        refresh_token="tb_irt_current",
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        generation=2,
        oauth_client_id="tether-agent-cli",
        family_id="family-1",
    )

    with pytest.raises(RuntimeError, match="generation changed"):
        store.finish_credential_refresh(
            expected_generation=1,
            access_token="tb_iat_wrong",
            refresh_token="tb_irt_wrong",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            generation=3,
        )

    credential = store.credential()
    assert credential is not None
    assert credential.access_token == "tb_iat_current"
    assert credential.refresh_token == "tb_irt_current"
    assert credential.generation == 2


@pytest.mark.asyncio
async def test_callback_state_and_issuer_are_validated_before_code_exchange(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    session = {
        "state_value": "expected-state",
        "issuer": "https://tetherbrain.net",
    }

    with pytest.raises(RuntimeError, match="state"):
        await _exchange_and_complete(
            callback={
                "state": "altered-state",
                "iss": "https://tetherbrain.net",
                "code": "tb_sac_hidden",
            },
            session=session,
            store=store,
        )

    with pytest.raises(RuntimeError, match="issuer"):
        await _exchange_and_complete(
            callback={
                "state": "expected-state",
                "iss": "https://attacker.example",
                "code": "tb_sac_hidden",
            },
            session=session,
            store=store,
        )


@pytest.mark.asyncio
async def test_token_nonce_is_validated_before_installation_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *args: object) -> None:
            del args

        async def post(self, url: str, **kwargs: object) -> httpx.Response:
            del kwargs
            return httpx.Response(
                200,
                json={"access_token": "tb_sat_hidden", "nonce": "wrong-nonce"},
                request=httpx.Request("POST", url),
            )

    monkeypatch.setattr(
        oauth_module.httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(),
    )
    store = StateStore(tmp_path / "state.sqlite3")
    session = {
        "state_value": "expected-state",
        "issuer": "https://tetherbrain.net",
        "nonce_value": "expected-nonce",
        "token_endpoint": "https://tetherbrain.net/oauth/token",
        "client_id": "tether-agent-cli",
        "redirect_uri": "http://127.0.0.1:49152/callback",
        "code_verifier": "verifier",
    }

    with pytest.raises(RuntimeError, match="nonce"):
        await _exchange_and_complete(
            callback={
                "state": "expected-state",
                "iss": "https://tetherbrain.net",
                "code": "tb_sac_hidden",
            },
            session=session,
            store=store,
        )

    assert store.credential() is None
