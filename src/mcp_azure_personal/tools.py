"""Personal Azure MCP tools.

This server owns the Azure surfaces we want to expose to tank-operator
sessions. Keep write operations explicit, parameterized, and guarded by
point-read identifiers or exact confirmations rather than accepting arbitrary
remote scripts.
"""

from __future__ import annotations

import os
import time
from typing import Any

import requests
from azure.core import MatchConditions
from azure.cosmos import CosmosClient
from azure.cosmos.exceptions import CosmosHttpResponseError, CosmosResourceNotFoundError
from azure.identity import DefaultAzureCredential, WorkloadIdentityCredential
from mcp.server.fastmcp import FastMCP


ARM = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
KEYVAULT_SCOPE = "https://vault.azure.net/.default"
KEYVAULT_API_VERSION = "7.4"
RESOURCES_API_VERSION = "2021-04-01"
STATIC_SITE_API_VERSION = "2024-04-01"
RESOURCE_GROUP_API_VERSION = "2024-11-01"
AKS_API_VERSION = "2024-10-01"
MANAGED_IDENTITY_API_VERSION = "2023-01-31"
POLL_TIMEOUT_SECONDS = 600
DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 1000
MAX_COSMOS_RESPONSE_ITEMS = 1000


def _subscription(subscription: str | None) -> str:
    sub = subscription or os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub:
        raise ValueError("subscription is required when AZURE_SUBSCRIPTION_ID is not set")
    return sub


def _credential() -> WorkloadIdentityCredential | DefaultAzureCredential:
    client_id = os.environ.get("AZURE_CLIENT_ID")
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE")
    if client_id and tenant_id and token_file:
        return WorkloadIdentityCredential(
            client_id=client_id,
            tenant_id=tenant_id,
            token_file_path=token_file,
        )
    return DefaultAzureCredential(exclude_interactive_browser_credential=True)


def _headers() -> dict[str, str]:
    token = _credential().get_token(ARM_SCOPE).token
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _graph_headers() -> dict[str, str]:
    token = _credential().get_token(GRAPH_SCOPE).token
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _cosmos_endpoint(account: str, account_endpoint: str | None = None) -> str:
    if account_endpoint:
        return account_endpoint.rstrip("/")
    if not account:
        raise ValueError("account is required")
    return f"https://{account}.documents.azure.com:443/"


def _cosmos_container(
    *,
    account: str,
    database: str,
    container: str,
    account_endpoint: str | None = None,
):
    client = CosmosClient(
        _cosmos_endpoint(account, account_endpoint),
        credential=_credential(),
    )
    return client.get_database_client(database).get_container_client(container)


def _bounded_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_QUERY_LIMIT
    if limit < 1 or limit > MAX_QUERY_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_QUERY_LIMIT}")
    return limit


def _query_with_limit(query: str, limit: int) -> str:
    stripped = query.lstrip()
    if stripped[:6].lower() == "select" and " top " not in stripped[:80].lower():
        return "SELECT TOP @__limit" + stripped[6:]
    return query


def _query_parameters(
    parameters: list[dict[str, Any]] | None,
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    result = list(parameters or [])
    if limit is not None:
        if any(p.get("name") == "@__limit" for p in result):
            raise ValueError("parameters must not include reserved @__limit")
        result.append({"name": "@__limit", "value": limit})
    return result


def _jsonable_doc(doc: Any) -> Any:
    if isinstance(doc, dict):
        return {k: _jsonable_doc(v) for k, v in doc.items() if not str(k).startswith("_")}
    if isinstance(doc, list):
        return [_jsonable_doc(v) for v in doc]
    return doc


def _etag(doc: dict[str, Any]) -> str | None:
    value = doc.get("_etag")
    return str(value) if value is not None else None


def _read_item(
    *,
    account: str,
    database: str,
    container: str,
    item_id: str,
    partition_key: Any,
    account_endpoint: str | None = None,
) -> dict[str, Any]:
    proxy = _cosmos_container(
        account=account,
        database=database,
        container=container,
        account_endpoint=account_endpoint,
    )
    try:
        return proxy.read_item(item=item_id, partition_key=partition_key)
    except CosmosResourceNotFoundError as exc:
        raise RuntimeError(
            f"Cosmos item not found: {database}/{container} id={item_id!r} "
            f"partition_key={partition_key!r}"
        ) from exc


def _validate_patch_operations(operations: list[dict[str, Any]]) -> None:
    if not operations:
        raise ValueError("operations must contain at least one patch operation")
    if len(operations) > 20:
        raise ValueError("operations may contain at most 20 patch operations")
    allowed = {"add", "replace", "remove", "set", "incr"}
    for index, op in enumerate(operations):
        name = op.get("op")
        path = op.get("path")
        if name not in allowed:
            raise ValueError(f"operations[{index}].op must be one of {sorted(allowed)}")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError(f"operations[{index}].path must be a JSON pointer path")
        if name not in {"remove"} and "value" not in op:
            raise ValueError(f"operations[{index}] requires value for op={name!r}")


def _normalize_match_condition(match_condition: str | None) -> MatchConditions | None:
    if match_condition is None:
        return None
    normalized = match_condition.lower().replace("_", "-")
    if normalized == "if-match":
        return MatchConditions.IfNotModified
    if normalized == "if-none-match":
        return MatchConditions.IfMissing
    if normalized not in {"if-match", "if-none-match"}:
        raise ValueError("match_condition must be 'if-match' or 'if-none-match'")
    raise RuntimeError("unreachable")


def _cosmos_write_result(
    *,
    account: str,
    database: str,
    container: str,
    item: dict[str, Any],
    include_item: bool,
) -> dict[str, Any]:
    return {
        "account": account,
        "database": database,
        "container": container,
        "id": item.get("id"),
        "partition_key": item.get("project") or item.get("partitionKey"),
        "etag": _etag(item),
        "item": _jsonable_doc(item) if include_item else None,
    }


def _request(
    method: str,
    path: str,
    *,
    ok: set[int],
    json: dict[str, Any] | None = None,
) -> requests.Response:
    resp = requests.request(method, f"{ARM}{path}", headers=_headers(), json=json, timeout=30)
    if resp.status_code not in ok:
        detail = resp.text.strip()
        raise RuntimeError(f"Azure ARM {method} {path} failed with {resp.status_code}: {detail}")
    return resp


def _kv_headers() -> dict[str, str]:
    token = _credential().get_token(KEYVAULT_SCOPE).token
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _normalize_vault_url(vault_url: str) -> str:
    cleaned = vault_url.strip().rstrip("/")
    if not cleaned.startswith(("https://", "http://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def _kv_request(
    method: str,
    vault_url: str,
    path: str,
    *,
    ok: set[int],
    json: dict[str, Any] | None = None,
    extra_query: dict[str, str] | None = None,
) -> requests.Response:
    base = _normalize_vault_url(vault_url)
    if not path.startswith("/"):
        path = f"/{path}"
    query: list[str] = [f"api-version={KEYVAULT_API_VERSION}"]
    if extra_query:
        for key, value in extra_query.items():
            if value is not None and value != "":
                query.append(f"{key}={value}")
    url = f"{base}{path}?{'&'.join(query)}"
    resp = requests.request(method, url, headers=_kv_headers(), json=json, timeout=30)
    if resp.status_code not in ok:
        detail = resp.text.strip()
        raise RuntimeError(f"Azure Key Vault {method} {path} failed with {resp.status_code}: {detail}")
    return resp


def _graph_request(
    method: str,
    path: str,
    *,
    ok: set[int],
    json: dict[str, Any] | None = None,
) -> requests.Response:
    resp = requests.request(method, f"{GRAPH}{path}", headers=_graph_headers(), json=json, timeout=30)
    if resp.status_code not in ok:
        detail = resp.text.strip()
        raise RuntimeError(f"Microsoft Graph {method} {path} failed with {resp.status_code}: {detail}")
    return resp


def _graph_filter_literal(value: str) -> str:
    return value.replace("'", "''")


def _normalize_redirect_uri(uri: str) -> str:
    normalized = str(uri or "").strip()
    if not normalized:
        raise ValueError("redirect URI must not be empty")
    if not normalized.startswith("https://") and "localhost" not in normalized:
        raise ValueError(f"redirect URI must be https unless localhost: {uri!r}")
    return normalized


def _normalize_fic_name(name: str) -> str:
    normalized = str(name or "").strip()
    if not normalized:
        raise ValueError("federated credential name must not be empty")
    if len(normalized) > 120:
        raise ValueError("federated credential name must be at most 120 characters")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if any(ch not in allowed for ch in normalized):
        raise ValueError("federated credential name may only contain letters, numbers, '-', '_', and '.'")
    return normalized


def _normalize_subject(subject: str) -> str:
    normalized = str(subject or "").strip()
    if not normalized:
        raise ValueError("subject must not be empty")
    if not normalized.startswith("system:serviceaccount:"):
        raise ValueError("subject must be a Kubernetes service-account subject")
    parts = normalized.split(":")
    if len(parts) != 4 or not parts[2] or not parts[3]:
        raise ValueError("subject must be system:serviceaccount:<namespace>:<serviceaccount>")
    return normalized


def _normalize_audiences(audiences: list[str] | None) -> list[str]:
    values = audiences or ["api://AzureADTokenExchange"]
    normalized = []
    seen = set()
    for audience in values:
        value = str(audience or "").strip()
        if not value:
            raise ValueError("audience must not be empty")
        if value not in seen:
            normalized.append(value)
            seen.add(value)
    if "api://AzureADTokenExchange" not in normalized:
        raise ValueError("audiences must include api://AzureADTokenExchange")
    return normalized


def _uami_fic_path(
    *,
    subscription: str | None,
    resource_group: str,
    identity_name: str,
    credential_name: str | None = None,
) -> str:
    sub = _subscription(subscription)
    base = (
        f"/subscriptions/{sub}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identity_name}"
        "/federatedIdentityCredentials"
    )
    return f"{base}/{credential_name}" if credential_name else base


def _resolve_application(
    *,
    application_object_id: str | None = None,
    application_app_id: str | None = None,
    display_name: str | None = None,
) -> dict[str, Any]:
    if application_object_id:
        return _graph_request(
            "GET",
            f"/applications/{application_object_id}",
            ok={200},
        ).json()
    if application_app_id:
        return _graph_request(
            "GET",
            f"/applications(appId='{_graph_filter_literal(application_app_id)}')",
            ok={200},
        ).json()
    if not display_name:
        raise ValueError("application_object_id, application_app_id, or display_name is required")
    payload = _graph_request(
        "GET",
        "/applications"
        f"?$filter=displayName eq '{_graph_filter_literal(display_name)}'"
        "&$select=id,appId,displayName,spa,web,publicClient",
        ok={200},
    ).json()
    items = payload.get("value") or []
    if not items:
        raise RuntimeError(f"application not found with display_name={display_name!r}")
    if len(items) > 1:
        ids = ", ".join(str(item.get("id")) for item in items)
        raise RuntimeError(f"display_name={display_name!r} matched multiple applications: {ids}")
    return items[0]


def _resource_path(path: str, subscription: str | None = None) -> str:
    normalized = path if path.startswith("/") else f"/{path}"
    if normalized.startswith("/subscriptions/"):
        return normalized
    if normalized.startswith("/resourceGroups/") or normalized.startswith("/providers/"):
        return f"/subscriptions/{_subscription(subscription)}{normalized}"
    raise ValueError(
        "path must start with /subscriptions/, /resourceGroups/, or /providers/"
    )


def _poll(location: str, *, timeout_seconds: int = POLL_TIMEOUT_SECONDS) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        resp = requests.get(location, headers=_headers(), timeout=30)
        if resp.status_code not in {200, 201, 202, 204}:
            raise RuntimeError(f"Azure ARM poll failed with {resp.status_code}: {resp.text.strip()}")
        if resp.status_code == 204 or not resp.text:
            return {"status": "Succeeded"}

        payload = resp.json()
        status = str(payload.get("status") or payload.get("properties", {}).get("provisioningState") or "")
        if status.lower() in {"succeeded", "failed", "canceled", "cancelled"}:
            if status.lower() != "succeeded":
                raise RuntimeError(f"Azure operation ended with {status}: {payload}")
            return payload

        if time.monotonic() >= deadline:
            raise TimeoutError(f"Azure operation did not finish within {timeout_seconds}s")
        time.sleep(5)


def _operation_url(resp: requests.Response) -> str | None:
    return resp.headers.get("Azure-AsyncOperation") or resp.headers.get("Location")


def _run_command_logs(payload: dict[str, Any]) -> str:
    properties = payload.get("properties") if isinstance(payload.get("properties"), dict) else {}
    for key in ("logs", "output", "result"):
        value = properties.get(key) or payload.get(key)
        if isinstance(value, str):
            return value
    return ""


def _truncate_text(text: str, max_chars: int | None, *, tail: bool = False) -> str:
    if max_chars is None or len(text) <= max_chars:
        return text
    if max_chars <= 0:
        return ""
    clipped = text[-max_chars:] if tail else text[:max_chars]
    marker = "\n... <truncated> ...\n"
    return f"{marker}{clipped}" if tail else f"{clipped}{marker}"


def _require_confirmation(value: str, confirmation: str | None, label: str) -> None:
    if confirmation != value:
        raise ValueError(f"{label} confirmation must exactly equal {value!r}")


def register_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def arm_list_resources(
        resource_group: str | None = None,
        resource_type: str | None = None,
        subscription: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List Azure resources from ARM.

        Use for lightweight discovery before calling a focused tool. Set
        `resource_group` to scope the list, and `resource_type` to filter by
        a provider type such as `Microsoft.DocumentDB/databaseAccounts`.
        """
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        sub = _subscription(subscription)
        if resource_group:
            path = (
                f"/subscriptions/{sub}/resourceGroups/{resource_group}/resources"
                f"?api-version={RESOURCES_API_VERSION}"
            )
        else:
            path = f"/subscriptions/{sub}/resources?api-version={RESOURCES_API_VERSION}"
        payload = _request("GET", path, ok={200}).json()
        resources = []
        for item in payload.get("value", []):
            if resource_type and str(item.get("type", "")).lower() != resource_type.lower():
                continue
            resources.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "type": item.get("type"),
                    "resource_group": str(item.get("id", "")).split("/resourceGroups/")[-1].split("/")[0],
                    "location": item.get("location"),
                    "tags": item.get("tags") or {},
                }
            )
            if len(resources) >= limit:
                break
        return {
            "subscription": sub,
            "resource_group": resource_group,
            "resource_type": resource_type,
            "count": len(resources),
            "resources": resources,
            "truncated": len(resources) >= limit,
        }

    @mcp.tool()
    def arm_get_resource(
        path: str,
        api_version: str,
        subscription: str | None = None,
    ) -> dict[str, Any]:
        """Read one Azure resource from ARM by resource path and API version.

        `path` may be a full `/subscriptions/...` resource ID, or a
        subscription-relative `/resourceGroups/...` or `/providers/...` path.
        """
        if not api_version:
            raise ValueError("api_version is required")
        resolved = _resource_path(path, subscription)
        separator = "&" if "?" in resolved else "?"
        payload = _request(
            "GET",
            f"{resolved}{separator}api-version={api_version}",
            ok={200},
        ).json()
        return {
            "path": resolved,
            "api_version": api_version,
            "resource": payload,
        }

    @mcp.tool()
    def entra_upsert_spa_redirect_uris(
        redirect_uris: list[str],
        application_object_id: str | None = None,
        application_app_id: str | None = None,
        display_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Add SPA redirect URIs to one Entra app registration.

        Resolve the app by exact `application_object_id` or exact
        `application_app_id` (client id), or exact `display_name`. Prefer
        `application_app_id` or `application_object_id`; display-name lookup
        may need broader directory read permission. The tool preserves existing
        SPA redirect URIs and only appends missing values. `dry_run` defaults
        true; pass false to write.

        Use for native webapp validation hosts whose browser login uses
        MSAL.js with `redirectUri = window.location.origin + "/"`.
        """
        wanted = []
        seen = set()
        for uri in redirect_uris:
            normalized = _normalize_redirect_uri(uri)
            if normalized not in seen:
                wanted.append(normalized)
                seen.add(normalized)
        if not wanted:
            raise ValueError("redirect_uris must contain at least one URI")

        app = _resolve_application(
            application_object_id=application_object_id,
            application_app_id=application_app_id,
            display_name=display_name,
        )
        app_id = str(app.get("id") or "")
        current = list(((app.get("spa") or {}).get("redirectUris")) or [])
        merged = list(current)
        added = []
        for uri in wanted:
            if uri not in merged:
                merged.append(uri)
                added.append(uri)

        if not dry_run and added:
            _graph_request(
                "PATCH",
                f"/applications/{app_id}",
                ok={204},
                json={"spa": {"redirectUris": merged}},
            )

        return {
            "dry_run": dry_run,
            "application_object_id": app_id,
            "app_id": app.get("appId"),
            "display_name": app.get("displayName"),
            "existing_redirect_uris": current,
            "requested_redirect_uris": wanted,
            "added_redirect_uris": added,
            "redirect_uris": merged,
            "changed": bool(added),
        }

    @mcp.tool()
    def uami_upsert_federated_credential(
        resource_group: str,
        identity_name: str,
        credential_name: str,
        issuer: str,
        subject: str,
        audiences: list[str] | None = None,
        subscription: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Create or update one user-assigned managed identity FIC.

        Use for Kubernetes workload-identity subjects owned by dynamic
        validation slots. The caller must pass the exact UAMI resource group
        and name plus the exact Kubernetes service-account subject
        (`system:serviceaccount:<namespace>:<serviceaccount>`). Existing
        credentials with the same name are preserved when their issuer,
        subject, and audiences already match. `dry_run` defaults true; pass
        false to write.
        """
        if not resource_group:
            raise ValueError("resource_group is required")
        if not identity_name:
            raise ValueError("identity_name is required")
        normalized_name = _normalize_fic_name(credential_name)
        normalized_subject = _normalize_subject(subject)
        normalized_issuer = str(issuer or "").strip()
        if not normalized_issuer.startswith("https://"):
            raise ValueError("issuer must be an https URL")
        normalized_audiences = _normalize_audiences(audiences)
        path = _uami_fic_path(
            subscription=subscription,
            resource_group=resource_group,
            identity_name=identity_name,
            credential_name=normalized_name,
        )

        current: dict[str, Any] | None = None
        resp = requests.get(
            f"{ARM}{path}?api-version={MANAGED_IDENTITY_API_VERSION}",
            headers=_headers(),
            timeout=30,
        )
        if resp.status_code == 200:
            current = resp.json()
        elif resp.status_code != 404:
            raise RuntimeError(
                f"Azure ARM GET {path} failed with {resp.status_code}: {resp.text.strip()}"
            )

        desired_properties = {
            "issuer": normalized_issuer,
            "subject": normalized_subject,
            "audiences": normalized_audiences,
        }
        current_properties = (current or {}).get("properties") or {}
        changed = (
            current is None
            or current_properties.get("issuer") != normalized_issuer
            or current_properties.get("subject") != normalized_subject
            or list(current_properties.get("audiences") or []) != normalized_audiences
        )

        if changed and not dry_run:
            _request(
                "PUT",
                f"{path}?api-version={MANAGED_IDENTITY_API_VERSION}",
                ok={200, 201},
                json={"properties": desired_properties},
            )

        return {
            "dry_run": dry_run,
            "subscription": _subscription(subscription),
            "resource_group": resource_group,
            "identity_name": identity_name,
            "credential_name": normalized_name,
            "resource_id": path,
            "existing": current_properties if current is not None else None,
            "desired": desired_properties,
            "changed": changed,
        }

    @mcp.tool()
    def cosmos_list(
        account: str | None = None,
        database: str | None = None,
        subscription: str | None = None,
    ) -> dict[str, Any]:
        """List Cosmos DB accounts, databases, or containers.

        Without `account`, lists Cosmos accounts in the subscription. With
        `account`, lists databases. With both `account` and `database`, lists
        containers. Uses ARM for account discovery and Cosmos data-plane APIs
        for database/container discovery.
        """
        sub = _subscription(subscription)
        if account is None:
            path = (
                f"/subscriptions/{sub}/providers/Microsoft.DocumentDB/databaseAccounts"
                "?api-version=2024-11-15"
            )
            payload = _request("GET", path, ok={200}).json()
            return {
                "subscription": sub,
                "accounts": [
                    {
                        "name": item.get("name"),
                        "resource_group": str(item.get("id", "")).split("/resourceGroups/")[-1].split("/")[0],
                        "location": item.get("location"),
                        "id": item.get("id"),
                    }
                    for item in payload.get("value", [])
                ],
            }

        client = CosmosClient(_cosmos_endpoint(account), credential=_credential())
        if database is None:
            return {
                "account": account,
                "databases": [db["id"] for db in client.list_databases()],
            }
        db = client.get_database_client(database)
        return {
            "account": account,
            "database": database,
            "containers": [c["id"] for c in db.list_containers()],
        }

    @mcp.tool()
    def cosmos_query_items(
        account: str,
        database: str,
        container: str,
        query: str = "SELECT * FROM c",
        parameters: list[dict[str, Any]] | None = None,
        limit: int | None = DEFAULT_QUERY_LIMIT,
        partition_key: Any | None = None,
        include_raw: bool = False,
        account_endpoint: str | None = None,
    ) -> dict[str, Any]:
        """Query items from a Cosmos DB SQL API container.

        `parameters` follows the Cosmos shape: `[{"name":"@p","value":"x"}]`.
        `limit` defaults to 100 and is injected as `TOP @__limit` for simple
        SELECT queries that do not already specify TOP.
        """
        bounded = _bounded_limit(limit)
        proxy = _cosmos_container(
            account=account,
            database=database,
            container=container,
            account_endpoint=account_endpoint,
        )
        kwargs: dict[str, Any] = {
            "query": _query_with_limit(query, bounded),
            "parameters": _query_parameters(parameters, limit=bounded),
            "enable_cross_partition_query": partition_key is None,
        }
        if partition_key is not None:
            kwargs["partition_key"] = partition_key
        items = []
        for item in proxy.query_items(**kwargs):
            items.append(item if include_raw else _jsonable_doc(item))
            if len(items) >= MAX_COSMOS_RESPONSE_ITEMS:
                break
        return {
            "account": account,
            "database": database,
            "container": container,
            "count": len(items),
            "items": items,
            "truncated": len(items) >= MAX_COSMOS_RESPONSE_ITEMS,
        }

    @mcp.tool()
    def cosmos_read_item(
        account: str,
        database: str,
        container: str,
        item_id: str,
        partition_key: Any,
        include_raw: bool = False,
        account_endpoint: str | None = None,
    ) -> dict[str, Any]:
        """Point-read one Cosmos DB item by id and partition key."""
        doc = _read_item(
            account=account,
            database=database,
            container=container,
            item_id=item_id,
            partition_key=partition_key,
            account_endpoint=account_endpoint,
        )
        return {
            "account": account,
            "database": database,
            "container": container,
            "id": item_id,
            "partition_key": partition_key,
            "etag": _etag(doc),
            "item": doc if include_raw else _jsonable_doc(doc),
        }

    @mcp.tool()
    def cosmos_patch_item(
        account: str,
        database: str,
        container: str,
        item_id: str,
        partition_key: Any,
        operations: list[dict[str, Any]],
        etag: str | None = None,
        match_condition: str | None = None,
        dry_run: bool = True,
        include_item: bool = False,
        account_endpoint: str | None = None,
    ) -> dict[str, Any]:
        """Patch one Cosmos DB item by id and partition key.

        `dry_run` defaults true and returns the current item etag plus the
        requested operations without writing. For writes, pass `dry_run=false`.
        When you have a current etag, pass `etag` and `match_condition="if-match"`
        for optimistic concurrency.
        """
        _validate_patch_operations(operations)
        before = _read_item(
            account=account,
            database=database,
            container=container,
            item_id=item_id,
            partition_key=partition_key,
            account_endpoint=account_endpoint,
        )
        if dry_run:
            return {
                "dry_run": True,
                "account": account,
                "database": database,
                "container": container,
                "id": item_id,
                "partition_key": partition_key,
                "etag": _etag(before),
                "operations": operations,
                "item": _jsonable_doc(before) if include_item else None,
            }
        proxy = _cosmos_container(
            account=account,
            database=database,
            container=container,
            account_endpoint=account_endpoint,
        )
        try:
            updated = proxy.patch_item(
                item=item_id,
                partition_key=partition_key,
                patch_operations=operations,
                etag=etag,
                match_condition=_normalize_match_condition(match_condition),
            )
        except CosmosHttpResponseError as exc:
            raise RuntimeError(f"Cosmos patch failed: {exc}") from exc
        result = _cosmos_write_result(
            account=account,
            database=database,
            container=container,
            item=updated,
            include_item=include_item,
        )
        result["dry_run"] = False
        result["operations"] = operations
        return result

    @mcp.tool()
    def cosmos_replace_item(
        account: str,
        database: str,
        container: str,
        item_id: str,
        partition_key: Any,
        item: dict[str, Any],
        etag: str | None = None,
        match_condition: str | None = None,
        dry_run: bool = True,
        include_item: bool = False,
        account_endpoint: str | None = None,
    ) -> dict[str, Any]:
        """Replace one Cosmos DB item by id and partition key.

        Use for whole-document writes when patch is not enough. `dry_run`
        defaults true. The replacement document must include the same `id`.
        """
        if item.get("id") != item_id:
            raise ValueError("replacement item must include the same id as item_id")
        before = _read_item(
            account=account,
            database=database,
            container=container,
            item_id=item_id,
            partition_key=partition_key,
            account_endpoint=account_endpoint,
        )
        if dry_run:
            return {
                "dry_run": True,
                "account": account,
                "database": database,
                "container": container,
                "id": item_id,
                "partition_key": partition_key,
                "etag": _etag(before),
                "replacement": _jsonable_doc(item) if include_item else None,
            }
        proxy = _cosmos_container(
            account=account,
            database=database,
            container=container,
            account_endpoint=account_endpoint,
        )
        updated = proxy.replace_item(
            item=item_id,
            body=item,
            etag=etag,
            match_condition=_normalize_match_condition(match_condition),
        )
        result = _cosmos_write_result(
            account=account,
            database=database,
            container=container,
            item=updated,
            include_item=include_item,
        )
        result["dry_run"] = False
        return result

    @mcp.tool()
    def cosmos_upsert_item(
        account: str,
        database: str,
        container: str,
        item: dict[str, Any],
        dry_run: bool = True,
        include_item: bool = False,
        account_endpoint: str | None = None,
    ) -> dict[str, Any]:
        """Upsert one Cosmos DB item.

        `dry_run` defaults true. Prefer patch or replace when updating an
        existing item; use upsert when idempotently seeding known documents.
        """
        item_id = item.get("id")
        if not item_id:
            raise ValueError("item.id is required")
        if dry_run:
            return {
                "dry_run": True,
                "account": account,
                "database": database,
                "container": container,
                "id": item_id,
                "item": _jsonable_doc(item) if include_item else None,
            }
        proxy = _cosmos_container(
            account=account,
            database=database,
            container=container,
            account_endpoint=account_endpoint,
        )
        updated = proxy.upsert_item(body=item)
        result = _cosmos_write_result(
            account=account,
            database=database,
            container=container,
            item=updated,
            include_item=include_item,
        )
        result["dry_run"] = False
        return result

    @mcp.tool()
    def cosmos_delete_item(
        account: str,
        database: str,
        container: str,
        item_id: str,
        partition_key: Any,
        etag: str | None = None,
        match_condition: str | None = None,
        dry_run: bool = True,
        account_endpoint: str | None = None,
    ) -> dict[str, Any]:
        """Delete one Cosmos DB item by id and partition key.

        Destructive. `dry_run` defaults true and returns the current
        etag plus the resolved id/partition_key without writing — so
        callers can inspect what would be deleted before flipping
        `dry_run=false`. When you have a current etag, pass `etag` and
        `match_condition="if-match"` for optimistic concurrency.
        """
        before = _read_item(
            account=account,
            database=database,
            container=container,
            item_id=item_id,
            partition_key=partition_key,
            account_endpoint=account_endpoint,
        )
        if dry_run:
            return {
                "dry_run": True,
                "account": account,
                "database": database,
                "container": container,
                "id": item_id,
                "partition_key": partition_key,
                "etag": _etag(before),
            }
        proxy = _cosmos_container(
            account=account,
            database=database,
            container=container,
            account_endpoint=account_endpoint,
        )
        proxy.delete_item(
            item=item_id,
            partition_key=partition_key,
            etag=etag,
            match_condition=_normalize_match_condition(match_condition),
        )
        return {
            "dry_run": False,
            "deleted": True,
            "account": account,
            "database": database,
            "container": container,
            "id": item_id,
            "partition_key": partition_key,
        }

    @mcp.tool()
    def delete_static_web_app(
        resource_group: str,
        name: str,
        confirm_name: str,
        subscription: str | None = None,
    ) -> dict[str, Any]:
        """Delete an Azure Static Web App resource by resource group and name.

        Destructive Azure cleanup tool. Use for removing disposable Static Web
        Apps when the regular Azure MCP cannot perform deletion. Destructive
        guard: confirm_name must exactly match name.
        """
        _require_confirmation(name, confirm_name, "static web app name")
        sub = _subscription(subscription)
        path = (
            f"/subscriptions/{sub}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Web/staticSites/{name}"
            f"?api-version={STATIC_SITE_API_VERSION}"
        )
        resp = _request("DELETE", path, ok={200, 202, 204})
        if resp.status_code == 202 and (operation_url := _operation_url(resp)):
            _poll(operation_url)
        return {
            "deleted": True,
            "subscription": sub,
            "resource_group": resource_group,
            "name": name,
            "type": "Microsoft.Web/staticSites",
        }

    @mcp.tool()
    def delete_resource_group(
        resource_group: str,
        confirm_resource_group: str,
        subscription: str | None = None,
    ) -> dict[str, Any]:
        """Delete an Azure resource group and every resource contained in it.

        Highly destructive Azure cleanup tool. Use only after listing/verifying
        the group is disposable. Destructive guard: confirm_resource_group must exactly match
        resource_group. Use only after verifying the group is disposable.
        """
        _require_confirmation(resource_group, confirm_resource_group, "resource group")
        sub = _subscription(subscription)
        path = (
            f"/subscriptions/{sub}/resourcegroups/{resource_group}"
            f"?api-version={RESOURCE_GROUP_API_VERSION}"
        )
        resp = _request("DELETE", path, ok={200, 202, 204})
        if resp.status_code == 202 and (operation_url := _operation_url(resp)):
            _poll(operation_url)
        return {
            "deleted": True,
            "subscription": sub,
            "resource_group": resource_group,
        }

    @mcp.tool()
    def run_aks_command(
        resource_group: str,
        cluster: str,
        command: str,
        subscription: str | None = None,
        context: str = "",
        timeout_seconds: int = POLL_TIMEOUT_SECONDS,
        line_contains: str | None = None,
        max_chars: int | None = 40_000,
    ) -> dict[str, Any]:
        """Run a command against an AKS cluster through Azure Run Command.

        Use for targeted kubectl inspection or one-off migration operations
        against a cluster that is not the caller's in-cluster Kubernetes API.
        `context`, when provided, must be a base64 encoded zip file accepted by
        AKS Run Command. Requires the personal Azure MCP identity to have Azure
        permissions for Microsoft.ContainerService/managedClusters/runCommand/action.
        `line_contains` and `max_chars` keep returned command logs compact.
        """
        if not command.strip():
            raise ValueError("command is required")
        if timeout_seconds < 30 or timeout_seconds > 1800:
            raise ValueError("timeout_seconds must be between 30 and 1800")

        sub = _subscription(subscription)
        path = (
            f"/subscriptions/{sub}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.ContainerService/managedClusters/{cluster}/runCommand"
            f"?api-version={AKS_API_VERSION}"
        )
        body = {
            "command": command,
            "context": context,
        }
        resp = _request("POST", path, ok={200, 201, 202}, json=body)

        payload: dict[str, Any]
        if resp.status_code == 202 and (operation_url := _operation_url(resp)):
            payload = _poll(operation_url, timeout_seconds=timeout_seconds)
        elif resp.text:
            payload = resp.json()
        else:
            payload = {"status": "Accepted"}

        logs = _run_command_logs(payload)
        if line_contains:
            needle = line_contains.lower()
            logs = "\n".join(line for line in logs.splitlines() if needle in line.lower())
        logs = _truncate_text(logs, max_chars, tail=True)

        return {
            "subscription": sub,
            "resource_group": resource_group,
            "cluster": cluster,
            "command": command,
            "logs": logs,
            "result": payload,
        }

    @mcp.tool()
    def keyvault_list_secrets(
        vault_url: str,
        name_contains: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List secret names + metadata in an Azure Key Vault.

        `vault_url` like `https://romaine-kv.vault.azure.net`. `name_contains`
        filters case-insensitively client-side. Values are not returned —
        call `keyvault_get_secret` for the value of one secret.
        """
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        secrets: list[dict[str, Any]] = []
        next_path = "/secrets"
        next_query: dict[str, str] = {"maxresults": "25"}
        while next_path:
            resp = _kv_request("GET", vault_url, next_path, ok={200}, extra_query=next_query)
            payload = resp.json()
            for item in payload.get("value", []):
                ident = str(item.get("id") or "")
                name = ident.rsplit("/", 1)[-1] if ident else ""
                if name_contains and name_contains.lower() not in name.lower():
                    continue
                attrs = item.get("attributes") or {}
                secrets.append(
                    {
                        "name": name,
                        "id": ident,
                        "enabled": attrs.get("enabled"),
                        "created": attrs.get("created"),
                        "updated": attrs.get("updated"),
                        "content_type": item.get("contentType"),
                        "tags": item.get("tags") or {},
                    }
                )
                if len(secrets) >= limit:
                    break
            if len(secrets) >= limit:
                break
            next_link = payload.get("nextLink") or ""
            if not next_link:
                break
            tail = next_link.split("?", 1)[-1]
            next_query = {}
            for chunk in tail.split("&"):
                if "=" in chunk and not chunk.startswith("api-version="):
                    key, value = chunk.split("=", 1)
                    next_query[key] = value
            next_path = "/secrets"
        return {
            "vault_url": _normalize_vault_url(vault_url),
            "name_contains": name_contains,
            "count": len(secrets),
            "truncated": len(secrets) >= limit,
            "secrets": secrets,
        }

    @mcp.tool()
    def keyvault_get_secret(
        vault_url: str,
        name: str,
        version: str | None = None,
    ) -> dict[str, Any]:
        """Read one Azure Key Vault secret value + metadata.

        Returns the plaintext `value` along with version, content_type, tags,
        and timestamps. Pass `version` to point-read a non-current version;
        omit to read the current version.
        """
        if not name:
            raise ValueError("name is required")
        path = f"/secrets/{name}"
        if version:
            path = f"/secrets/{name}/{version}"
        payload = _kv_request("GET", vault_url, path, ok={200}).json()
        attrs = payload.get("attributes") or {}
        ident = str(payload.get("id") or "")
        return {
            "vault_url": _normalize_vault_url(vault_url),
            "name": name,
            "id": ident,
            "version": ident.rsplit("/", 1)[-1] if ident.count("/") >= 4 else None,
            "value": payload.get("value"),
            "content_type": payload.get("contentType"),
            "tags": payload.get("tags") or {},
            "enabled": attrs.get("enabled"),
            "created": attrs.get("created"),
            "updated": attrs.get("updated"),
        }

    @mcp.tool()
    def keyvault_set_secret(
        vault_url: str,
        name: str,
        value: str,
        dry_run: bool = True,
        allow_create: bool = False,
        content_type: str | None = None,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Create a new version of an Azure Key Vault secret.

        `dry_run` defaults true and returns the current secret's metadata + a
        plaintext-vs-new diff summary (lengths, equality) without writing.

        `allow_create` defaults false: if `name` does not already exist in the
        vault, the call errors out so a typo cannot silently create a new
        secret. Set true to permit creation.

        `content_type` and `tags` are passed through to Key Vault when
        provided. Old versions are preserved automatically by Key Vault.
        """
        if not name:
            raise ValueError("name is required")
        if value is None:
            raise ValueError("value is required (use empty string for an explicit blank)")

        current_value: str | None = None
        current_attrs: dict[str, Any] = {}
        current_id: str | None = None
        current_content_type: str | None = None
        current_tags: dict[str, str] = {}
        existed = False
        try:
            payload = _kv_request("GET", vault_url, f"/secrets/{name}", ok={200}).json()
            existed = True
            current_value = payload.get("value")
            current_attrs = payload.get("attributes") or {}
            current_id = str(payload.get("id") or "")
            current_content_type = payload.get("contentType")
            current_tags = payload.get("tags") or {}
        except RuntimeError as exc:
            # 404 surfaces as a RuntimeError from _kv_request; only treat
            # SecretNotFound as "doesn't exist", surface other failures.
            if "404" not in str(exc):
                raise
            if not allow_create:
                raise RuntimeError(
                    f"secret {name!r} does not exist in {_normalize_vault_url(vault_url)}; "
                    "pass allow_create=true to create a new secret"
                ) from None

        diff = {
            "current_length": len(current_value) if current_value is not None else None,
            "new_length": len(value),
            "unchanged": current_value == value,
        }

        plan = {
            "vault_url": _normalize_vault_url(vault_url),
            "name": name,
            "existed": existed,
            "current_id": current_id,
            "current_content_type": current_content_type,
            "current_tags": current_tags,
            "current_attributes": current_attrs,
            "diff": diff,
            "would_create_new_secret": not existed,
        }

        if dry_run:
            plan["dry_run"] = True
            return plan

        body: dict[str, Any] = {"value": value}
        if content_type is not None:
            body["contentType"] = content_type
        if tags is not None:
            body["tags"] = tags
        resp = _kv_request("PUT", vault_url, f"/secrets/{name}", ok={200}, json=body).json()
        new_attrs = resp.get("attributes") or {}
        new_id = str(resp.get("id") or "")
        plan["dry_run"] = False
        plan["written"] = True
        plan["new_id"] = new_id
        plan["new_version"] = new_id.rsplit("/", 1)[-1] if new_id else None
        plan["new_attributes"] = new_attrs
        plan["new_content_type"] = resp.get("contentType")
        plan["new_tags"] = resp.get("tags") or {}
        return plan
