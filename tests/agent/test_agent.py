"""SENTINEL MATRIX — agent tests. Pure-logic tests run without fastapi/httpx installed;
the full API tests run only when the optional deps are present."""
import os, sys, json, py_compile, tempfile
import importlib.util

AGENT = os.path.join(os.path.dirname(__file__), "..", "..", "agent")
sys.path.insert(0, AGENT)


def test_all_agent_files_compile():
    for f in ("sentinel_matrix_agent.py", "siem_adapters.py", "credential_store.py"):
        py_compile.compile(os.path.join(AGENT, f), doraise=True)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(AGENT, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_qradar_helpers_without_httpx(monkeypatch):
    # siem_adapters imports httpx at top; only test if available, else test helpers via source exec
    try:
        import httpx  # noqa
    except ImportError:
        import types
        sys.modules["httpx"] = types.SimpleNamespace(AsyncClient=object, HTTPError=Exception)
    adapters = _load("siem_adapters")
    assert adapters._qradar_type(12) == "windows_security"
    assert adapters._qradar_type(99999) == "application"
    iso = adapters._ms_to_iso(1700000000000)
    assert iso and iso.endswith("Z") and iso.startswith("2023")
    assert adapters._ms_to_iso(None) is None
    # health: very old last event -> stale
    assert adapters._health_from_status({}, 1) == "stale"
    assert adapters._health_from_status({}, None) == "healthy"
    # tests flattening
    assert "a" in adapters._flatten_qradar_tests({"tests": [{"text": "a"}, {"text": "b"}]})
    assert adapters._flatten_qradar_tests({"tests": "literal"}) == "literal"
    assert set(adapters.ADAPTERS) == {"qradar", "splunk", "sentinel", "elastic"}


def test_credential_store_file_backend():
    cs = _load("credential_store")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "creds.json")
        store = cs.CredentialStore(path)
        store._keyring = None  # force file backend
        store.save("qradar", "siem.example.local", "SECRET-TOKEN-123")
        assert store.get("qradar", "siem.example.local") == "SECRET-TOKEN-123"
        # file permissions 0600 on POSIX
        if os.name == "posix":
            mode = oct(os.stat(path).st_mode)[-3:]
            assert mode == "600", mode
        store.remove("qradar", "siem.example.local")
        assert store.get("qradar", "siem.example.local") is None


def test_credential_store_no_backend_raises():
    cs = _load("credential_store")
    store = cs.CredentialStore(None)
    store._keyring = None
    raised = False
    try:
        store.save("qradar", "x", "t")
    except RuntimeError:
        raised = True
    assert raised


def test_api_read_only_and_health():
    try:
        import fastapi, httpx, pydantic  # noqa
        from fastapi.testclient import TestClient
    except ImportError:
        import pytest
        pytest.skip("fastapi/httpx not installed; skipping live API tests")
    # import app
    agent = _load("sentinel_matrix_agent")
    from credential_store import CredentialStore
    agent.STATE["config"] = {"allow_remote": True}
    agent.STATE["cred_store"] = CredentialStore(None)
    client = TestClient(agent.app)
    r = client.get("/health")
    assert r.status_code == 200
    j = r.json()
    assert j["read_only"] is True and j["status"] == "healthy"
    assert set(j["supported_platforms"]) == {"qradar", "splunk", "sentinel", "elastic"}
    # unsupported platform rejected
    r2 = client.post("/api/siem/connect", json={"platform": "nope", "host": "x", "token": "t"})
    assert r2.status_code == 422
    # no write endpoints exist
    assert client.post("/api/siem/rules/delete", json={}).status_code == 404
    assert client.post("/api/siem/deploy", json={}).status_code == 404
