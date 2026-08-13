"""Typed HTTP client for the local execution protocol."""

from collections.abc import Awaitable, Callable
from typing import Any
from uuid import UUID

import httpx


class AgentApiError(httpx.HTTPStatusError):
    """A redacted server error with retry guidance for daemon operations."""

    def __init__(self, response: httpx.Response) -> None:
        code = "agent_api_error"
        message = f"Tether Brain returned HTTP {response.status_code}"
        recoverable = response.status_code >= 500 or response.status_code == 429
        try:
            detail = response.json().get("detail")
        except (ValueError, AttributeError):
            detail = None
        if isinstance(detail, dict):
            code = str(detail.get("code") or code)
            message = str(detail.get("message") or message)
            recoverable = bool(detail.get("recoverable", recoverable))
        elif isinstance(detail, str) and detail:
            message = detail
        self.code = code
        self.user_message = message
        self.recoverable = recoverable
        super().__init__(message, request=response.request, response=response)


class TetherApi:
    def __init__(
        self,
        server_url: str,
        access_token: str,
        *,
        oauth_client_id: str | None = None,
        oauth_refresh_token: str | None = None,
        save_refresh_token: Callable[[str], None] | None = None,
        installation_token_provider: Callable[[bool], Awaitable[str]] | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=server_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30,
        )
        self._oauth_client_id = oauth_client_id
        self._oauth_refresh_token = oauth_refresh_token
        self._save_refresh_token = save_refresh_token
        self._installation_token_provider = installation_token_provider

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        if self._installation_token_provider is not None:
            token = await self._installation_token_provider(False)
            self._client.headers["Authorization"] = f"Bearer {token}"
        response = await self._client.request(method, url, **kwargs)
        if (
            response.status_code == 401
            and self._installation_token_provider is not None
        ):
            token = await self._installation_token_provider(True)
            self._client.headers["Authorization"] = f"Bearer {token}"
            return await self._client.request(method, url, **kwargs)
        if response.status_code != 401 or not (
            self._oauth_client_id and self._oauth_refresh_token
        ):
            return response
        refresh = await self._client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self._oauth_client_id,
                "refresh_token": self._oauth_refresh_token,
            },
        )
        refresh.raise_for_status()
        payload = refresh.json()
        access_token = str(payload["access_token"])
        self._oauth_refresh_token = str(payload["refresh_token"])
        self._client.headers["Authorization"] = f"Bearer {access_token}"
        if self._save_refresh_token is not None:
            self._save_refresh_token(self._oauth_refresh_token)
        return await self._client.request(method, url, **kwargs)

    async def close(self) -> None:
        await self._client.aclose()

    async def identity(self) -> dict[str, Any]:
        response = await self._request("GET", "/api/agent/me")
        response.raise_for_status()
        return response.json()

    async def register(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._request(
            "POST", "/api/agent/v1/installations/register", json=payload
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def liveness(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._request(
            "POST", "/api/agent/v1/installations/heartbeat", json=payload
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def report_runtime_catalog(
        self,
        installation_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        response = await self._request(
            "PUT",
            (f"/api/agent/v1/installations/{installation_id}/runtime-catalog"),
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    async def redeem_workspace_setup_reference(self, value: str) -> dict[str, Any]:
        response = await self._request(
            "POST",
            "/api/agent/v1/workspace-setup-references/redeem",
            json={"setup_reference": value},
        )
        response.raise_for_status()
        return response.json()

    async def claim(
        self,
        installation_id: UUID,
        *,
        worker_slot: int = 0,
        configured_capacity: int = 1,
        supported_features: tuple[str, ...] = (),
    ) -> dict[str, Any] | None:
        response = await self._request(
            "POST",
            "/api/agent/v1/runs/claim",
            json={
                "installation_id": str(installation_id),
                "worker_slot": worker_slot,
                "configured_capacity": configured_capacity,
                "supported_features": list(supported_features),
            },
        )
        if response.status_code == 204:
            return None
        response.raise_for_status()
        return response.json()

    async def checkpoint_task(
        self,
        run_id: UUID,
        task_id: UUID,
        generation: int,
        lease_token: str,
        *,
        turn_revision: int,
        checkpoint_revision: int,
        worktree_tree: str,
        summary: str,
        token_usage: dict[str, Any] | None,
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/tasks/{task_id}/checkpoint",
            json={
                "generation": generation,
                "lease_token": lease_token,
                "turn_revision": turn_revision,
                "checkpoint_revision": checkpoint_revision,
                "worktree_tree": worktree_tree,
                "summary": summary,
                "token_usage": token_usage,
            },
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def run(self, run_id: UUID) -> dict[str, Any]:
        response = await self._request("GET", f"/api/agent/v1/runs/{run_id}")
        response.raise_for_status()
        return response.json()

    async def heartbeat(self, run_id: UUID, generation: int, lease_token: str) -> None:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/heartbeat",
            json={"generation": generation, "lease_token": lease_token},
        )
        response.raise_for_status()

    async def context(
        self, run_id: UUID, generation: int, lease_token: str
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/context",
            json={"generation": generation, "lease_token": lease_token},
        )
        response.raise_for_status()
        return response.json()

    async def state(
        self,
        run_id: UUID,
        generation: int,
        lease_token: str,
        state: str,
        message: str | None = None,
        effective_model_id: str | None = None,
        effective_reasoning_effort: str | None = None,
        failure_code: str | None = None,
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/state",
            json={
                "generation": generation,
                "lease_token": lease_token,
                "state": state,
                "message": message,
                "failure_code": failure_code,
                "effective_model_id": effective_model_id,
                "effective_reasoning_effort": effective_reasoning_effort,
            },
        )
        response.raise_for_status()
        return response.json()

    async def timeline(
        self,
        run_id: UUID,
        generation: int,
        lease_token: str,
        key: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/timeline",
            headers={
                "X-Lease-Generation": str(generation),
                "X-Lease-Token": lease_token,
                "Idempotency-Key": key,
            },
            json={
                "kind": "progress",
                "message": message,
                "payload": payload or {},
            },
        )
        response.raise_for_status()

    async def token_usage(
        self,
        run_id: UUID,
        generation: int,
        lease_token: str,
        sequence: int,
        payload: dict[str, Any],
    ) -> None:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/token-usage",
            json={
                "generation": generation,
                "lease_token": lease_token,
                "sequence": sequence,
                **payload,
            },
        )
        if response.is_error:
            raise AgentApiError(response)

    async def comment(
        self,
        run_id: UUID,
        generation: int,
        lease_token: str,
        kind: str,
        body: str,
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/comments",
            headers={
                "Idempotency-Key": (f"daemon-comment:{run_id}:{generation}:{kind}")
            },
            json={
                "generation": generation,
                "lease_token": lease_token,
                "kind": kind,
                "body": body,
            },
        )
        response.raise_for_status()
        return response.json()

    async def complete(
        self,
        run_id: UUID,
        generation: int,
        lease_token: str,
        task_version: int,
        final_comment: str,
        outputs: list[dict[str, Any]],
        completion_note: dict[str, str] | None = None,
        change_set: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/complete",
            headers={"Idempotency-Key": f"daemon-complete:{run_id}"},
            json={
                "generation": generation,
                "lease_token": lease_token,
                "expected_task_version": task_version,
                "final_comment": final_comment,
                "outputs": outputs,
                "completion_note_title": (
                    completion_note["title"] if completion_note is not None else None
                ),
                "completion_note_markdown": (
                    completion_note["markdown"] if completion_note is not None else None
                ),
                "change_set": change_set,
            },
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def pending_handoffs(self, installation_id: UUID) -> list[dict[str, Any]]:
        response = await self._request(
            "GET",
            f"/api/agent/v1/installations/{installation_id}/handoffs",
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def start_handoff(
        self,
        run_id: UUID,
        binding: dict[str, Any],
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/handoff/start",
            json=binding,
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def report_handoff_status(
        self,
        run_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any] | None:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/handoff/status",
            json=payload,
        )
        if response.status_code in {404, 405}:
            return None
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def report_change_set_validation(
        self,
        run_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/change-set/validation",
            json=payload,
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def supersede_change_set(
        self,
        run_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/change-set/supersede",
            json=payload,
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def complete_handoff(
        self,
        run_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/handoff/complete",
            json=payload,
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def acknowledge_handoff(
        self,
        run_id: UUID,
        binding: dict[str, Any],
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/handoff/acknowledge",
            json=binding,
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def pending_publications(self, installation_id: UUID) -> list[dict[str, Any]]:
        response = await self._request(
            "GET",
            f"/api/agent/v1/installations/{installation_id}/publications",
        )
        if response.status_code in {404, 405}:
            return []
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def start_publication(
        self, run_id: UUID, binding: dict[str, Any]
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/publication/start",
            json=binding,
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()

    async def complete_publication(
        self, run_id: UUID, payload: dict[str, Any]
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/agent/v1/runs/{run_id}/publication/complete",
            json=payload,
        )
        if response.is_error:
            raise AgentApiError(response)
        return response.json()
