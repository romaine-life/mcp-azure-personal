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
RESOURCES_API_VERSION = "2021-04-01"
STATIC_SITE_API_VERSION = "2024-04-01"
RESOURCE_GROUP_API_VERSION = "2024-11-01"
AKS_API_VERSION = "2024-10-01"
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


def _resolve_application(
    *,
    application_object_id: str | None = None,
    display_name: str | None = None,
) -> dict[str, Any]:
    if application_object_id:
        return _graph_request(
            "GET",
            f"/applications/{application_object_id}",
            ok={200},
        ).json()
    if not display_name:
        raise ValueError("application_object_id or display_name is required")
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
        display_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Add SPA redirect URIs to one Entra app registration.

        Resolve the app by exact `application_object_id` or exact
        `display_name`. The tool preserves existing SPA redirect URIs and only
        appends missing values. `dry_run` defaults true; pass false to write.

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
