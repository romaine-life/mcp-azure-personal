from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from mcp_azure_personal import tools as tools_module
from mcp_azure_personal.tools import (
    _validate_pg_execute_sql,
    register_tools,
)


class _Recorder:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class _FakeCredential:
    def get_token(self, scope: str):
        return types.SimpleNamespace(token=f"token-for-{scope}")


class _Column:
    def __init__(self, name: str):
        self.name = name


class _FakeCursor:
    def __init__(
        self,
        *,
        rowcount: int = 1,
        rows: list[dict[str, Any]] | None = None,
    ):
        self.rowcount = rowcount
        self._rows = rows or []
        self.description = (
            [_Column(name) for name in self._rows[0].keys()]
            if self._rows
            else None
        )
        self.executed_sql: str | None = None
        self.executed_params: tuple[Any, ...] | None = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql: str, params: tuple[Any, ...]):
        self.executed_sql = sql
        self.executed_params = params

    def fetchmany(self, limit: int):
        return self._rows[:limit]


class _FakeConnection:
    def __init__(self, cursor: _FakeCursor):
        self.cursor_obj = cursor
        self.commits = 0
        self.rollbacks = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self, row_factory):
        assert row_factory == "dict_row"
        return self.cursor_obj

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


@pytest.fixture
def pg_tool(monkeypatch):
    recorder = _Recorder()
    register_tools(recorder)
    monkeypatch.setattr(tools_module, "_credential", lambda: _FakeCredential())
    return recorder.tools["pg_execute"]


def _install_fake_psycopg(monkeypatch, cursor: _FakeCursor):
    captured: dict[str, Any] = {}
    conn = _FakeConnection(cursor)

    def connect(**kwargs):
        captured["connect_kwargs"] = kwargs
        return conn

    monkeypatch.setitem(sys.modules, "psycopg", types.SimpleNamespace(connect=connect))
    monkeypatch.setitem(
        sys.modules,
        "psycopg.rows",
        types.SimpleNamespace(dict_row="dict_row"),
    )
    return conn, captured


def test_pg_execute_dry_run_rolls_back_and_returns_rows(pg_tool, monkeypatch):
    cursor = _FakeCursor(
        rowcount=1,
        rows=[{"session_id": "287", "visible": False}],
    )
    conn, captured = _install_fake_psycopg(monkeypatch, cursor)

    result = pg_tool(
        host="tank-operator-db.postgres.database.azure.com",
        database="tank-operator",
        user="mcp-azure-personal-identity",
        sql="update sessions set visible = %s where session_id = %s returning session_id, visible",
        parameters=[False, "287"],
    )

    assert result["dry_run"] is True
    assert result["committed"] is False
    assert result["row_count"] == 1
    assert result["columns"] == ["session_id", "visible"]
    assert result["rows"] == [{"session_id": "287", "visible": False}]
    assert conn.rollbacks == 1
    assert conn.commits == 0
    assert cursor.executed_params == (False, "287")
    assert "default_transaction_read_only" not in captured["connect_kwargs"]["options"]
    assert captured["connect_kwargs"]["application_name"] == "mcp-azure-personal pg_execute"


def test_pg_execute_commits_when_dry_run_false(pg_tool, monkeypatch):
    cursor = _FakeCursor(rowcount=2)
    conn, _captured = _install_fake_psycopg(monkeypatch, cursor)

    result = pg_tool(
        host="glimmung-pg.postgres.database.azure.com",
        database="glimmung",
        user="mcp-azure-personal-identity",
        sql="delete from leases where expired = %s",
        parameters=[True],
        dry_run=False,
        max_affected_rows=5,
    )

    assert result["dry_run"] is False
    assert result["committed"] is True
    assert result["row_count"] == 2
    assert conn.commits == 1
    assert conn.rollbacks == 0


def test_pg_execute_rolls_back_when_row_count_exceeds_cap(pg_tool, monkeypatch):
    cursor = _FakeCursor(rowcount=10)
    conn, _captured = _install_fake_psycopg(monkeypatch, cursor)

    with pytest.raises(ValueError, match="above max_affected_rows"):
        pg_tool(
            host="glimmung-pg.postgres.database.azure.com",
            database="glimmung",
            user="mcp-azure-personal-identity",
            sql="update slots set state = %s",
            parameters=["available"],
            dry_run=False,
            max_affected_rows=5,
        )

    assert conn.commits == 0
    assert conn.rollbacks == 1


def test_pg_execute_rejects_unallowlisted_host(pg_tool):
    with pytest.raises(ValueError, match="host is not allowed"):
        pg_tool(
            host="example.postgres.database.azure.com",
            database="app",
            user="mcp-azure-personal-identity",
            sql="update widgets set enabled = %s",
            parameters=[True],
        )


def test_pg_execute_sql_must_be_single_dml_statement():
    assert _validate_pg_execute_sql("/* repair */ update slots set state = %s") == "update"
    assert _validate_pg_execute_sql("update slots set detail = 'a;b'") == "update"

    with pytest.raises(ValueError, match="exactly one statement"):
        _validate_pg_execute_sql("update slots set state = %s; delete from leases")

    with pytest.raises(ValueError, match="only allows one data-changing statement"):
        _validate_pg_execute_sql("select * from slots")
