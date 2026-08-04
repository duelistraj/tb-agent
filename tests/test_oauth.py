from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Self

import httpx
import pytest

import tether_agent.oauth as oauth_module
from tether_agent.cli import build_parser, safe_error_message
from tether_agent.config import ProfileConfig
from tether_agent.oauth import (
    _exchange_and_complete,
    _oauth_login_unlocked,
    _origin,
    discover_oauth,
    pkce_pair,
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
