"""
SENTINEL MATRIX — modular, READ-ONLY SIEM adapters.

Each adapter implements: connect(), get_rules(), get_log_sources(), get_offenses(), get_alerts().
Adapters perform ONLY read operations. They never create, modify, enable/disable or delete
rules, offenses or configuration. Capability detection gracefully handles fields/endpoints that
a given SIEM version does not expose.

NOTE on QRadar: field and endpoint availability varies by QRadar version. We request a documented
set of fields and degrade gracefully (capability detection) rather than assuming everything exists.
"""
from __future__ import annotations
import asyncio, logging, time
from typing import Any, Optional
import httpx

LOG = logging.getLogger("sentinel-agent.adapters")

class SiemError(Exception):
    pass

class BaseAdapter:
    platform = "base"
    def __init__(self, host: str, port: int, secret: str, *, tls_verify: bool = True,
                 api_version: str = "", auth_method: str = "token", username: Optional[str] = None):
        self.host, self.port, self.secret = host, port, secret
        self.tls_verify, self.api_version, self.auth_method, self.username = tls_verify, api_version, auth_method, username
        self.base = f"https://{host}:{port}"
        self._client: Optional[httpx.AsyncClient] = None
        self.capabilities: dict[str, bool] = {}

    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(verify=self.tls_verify, timeout=30.0,
                                             headers=self._headers(), follow_redirects=False)
        return self._client

    def _headers(self) -> dict[str, str]:
        return {"Accept": "application/json"}

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _get(self, path: str, params: dict | None = None) -> Any:
        url = self.base + path
        try:
            r = await self.client().get(url, params=params)
        except httpx.HTTPError as e:
            raise SiemError(f"request to {path} failed: {type(e).__name__}: {e}")
        if r.status_code == 401:
            raise SiemError("authentication failed (401) — check the API token/credential and its privileges")
        if r.status_code == 403:
            raise SiemError("authorization failed (403) — the credential lacks read access to this resource")
        if r.status_code == 404:
            return None  # capability detection: endpoint not available on this version
        if r.status_code == 429:
            retry = int(r.headers.get("Retry-After", "2"))
            LOG.info("rate limited; backing off %ss", retry)
            await asyncio.sleep(min(retry, 10))
            r = await self.client().get(url, params=params)
        if r.status_code >= 400:
            raise SiemError(f"{path} returned HTTP {r.status_code}")
        try:
            return r.json()
        except Exception:
            raise SiemError(f"{path} did not return JSON")

    async def _paged(self, path: str, page_size: int = 500, limit: int = 5000,
                     range_header: bool = False) -> list[dict]:
        """Generic pagination. QRadar uses a Range header; others use offset/limit params."""
        out: list[dict] = []
        start = 0
        while len(out) < limit:
            if range_header:
                end = start + page_size - 1
                self.client().headers["Range"] = f"items={start}-{end}"
                data = await self._get(path)
                self.client().headers.pop("Range", None)
            else:
                data = await self._get(path, params={"offset": start, "count": page_size})
            if not data:
                break
            chunk = data if isinstance(data, list) else data.get("items") or data.get("data") or []
            if not chunk:
                break
            out.extend(chunk)
            if len(chunk) < page_size:
                break
            start += page_size
        return out[:limit]

    # subclasses override
    async def connect(self) -> dict: raise NotImplementedError
    async def get_rules(self, limit: int = 5000) -> list[dict]: return []
    async def get_log_sources(self) -> list[dict]: return []
    async def get_offenses(self, limit: int = 2000) -> list[dict]: return []
    async def get_alerts(self) -> list[dict]: return []


# ------------------------------- IBM QRadar -------------------------------
class QRadarAdapter(BaseAdapter):
    platform = "qradar"
    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json", "SEC": self.secret, "Version": self.api_version or "19.0"}
        return h

    async def connect(self) -> dict:
        about = await self._get("/api/system/about")
        if about is None:
            # try version endpoint
            about = await self._get("/api/help/versions") or {}
        # probe capabilities
        self.capabilities = {
            "rules": await self._probe("/api/analytics/rules"),
            "building_blocks": await self._probe("/api/analytics/building_blocks"),
            "log_sources": await self._probe("/api/config/event_sources/log_source_management/log_sources"),
            "offenses": await self._probe("/api/siem/offenses"),
            "reference_sets": await self._probe("/api/reference_data/sets"),
        }
        return {"api_version": (about or {}).get("external_version") or self.api_version or "unknown",
                "deployment": "IBM QRadar", "capabilities": self.capabilities}

    async def _probe(self, path: str) -> bool:
        try:
            self.client().headers["Range"] = "items=0-0"
            r = await self.client().get(self.base + path)
            self.client().headers.pop("Range", None)
            return r.status_code < 400
        except httpx.HTTPError:
            return False

    async def get_rules(self, limit: int = 5000) -> list[dict]:
        if not self.capabilities.get("rules", True):
            return []
        fields = "id,name,type,enabled,owner,origin,creation_date,modification_date,identifier"
        rules = await self._paged(f"/api/analytics/rules?fields={fields}", page_size=200, limit=limit, range_header=True)
        # best-effort enrichment with rule data (tests) where exposed
        for r in rules[:limit]:
            r.setdefault("identifier", str(r.get("id")))
            rd = await self._get(f"/api/analytics/rules/{r['id']}")
            if rd:
                r["rule_tests"] = _flatten_qradar_tests(rd)
                r["rule_groups"] = rd.get("rule_group_ids") or r.get("rule_groups")
        return rules

    async def get_log_sources(self) -> list[dict]:
        path = "/api/config/event_sources/log_source_management/log_sources"
        data = await self._paged(path + "?fields=id,name,enabled,type_id,last_event_time,status,hostname", page_size=200, limit=5000, range_header=True)
        out = []
        for l in data:
            st = l.get("status") or {}
            out.append({"id": str(l.get("id")), "source_name": l.get("name"), "source_type": _qradar_type(l.get("type_id")),
                        "hostname": l.get("hostname", ""), "collection_status": "active" if l.get("enabled") else "inactive",
                        "health_status": _health_from_status(st, l.get("last_event_time")),
                        "last_event": _ms_to_iso(l.get("last_event_time"))})
        return out

    async def get_offenses(self, limit: int = 2000) -> list[dict]:
        data = await self._paged("/api/siem/offenses?fields=id,description,magnitude,severity,status,event_count,offense_source,categories,start_time,last_updated_time,rules",
                                 page_size=100, limit=limit, range_header=True)
        out = []
        for o in data:
            out.append({"id": str(o.get("id")), "description": o.get("description", "").strip(),
                        "severity": o.get("severity"), "magnitude": o.get("magnitude"), "status": o.get("status", "OPEN"),
                        "event_count": o.get("event_count", 0), "source_ip": o.get("offense_source", ""),
                        "category": (o.get("categories") or [""])[0] if o.get("categories") else "",
                        "first_seen": _ms_to_iso(o.get("start_time")), "last_seen": _ms_to_iso(o.get("last_updated_time")),
                        "rule_ids": [str(r.get("id")) for r in (o.get("rules") or [])]})
        return out

    async def get_alerts(self) -> list[dict]:
        # QRadar surfaces alerting as offenses; discrete alert volume per rule is not a standard endpoint.
        return []


def _flatten_qradar_tests(rd: dict) -> str:
    tests = rd.get("tests") or rd.get("rule_tests") or []
    if isinstance(tests, str):
        return tests
    parts = []
    for t in tests:
        parts.append(t.get("text") or t.get("name") or "")
    return "\n".join(p for p in parts if p)

_QRADAR_TYPES = {12: "windows_security", 2: "linux_syslog", 13: "network_device", 11: "firewall",
                 55: "windows_security", 112: "dns", 7: "proxy", 331: "edr"}
def _qradar_type(type_id) -> str:
    return _QRADAR_TYPES.get(type_id, "application")
def _health_from_status(st: dict, last_event_ms) -> str:
    if last_event_ms and (time.time() * 1000 - last_event_ms) > 86400000:
        return "stale"
    if st and st.get("messages"):
        return "stale"
    return "healthy"
def _ms_to_iso(ms) -> Optional[str]:
    if not ms:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000))


# ------------------------------- Splunk ES -------------------------------
class SplunkAdapter(BaseAdapter):
    platform = "splunk"
    def _headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "Authorization": f"Bearer {self.secret}"}

    async def connect(self) -> dict:
        info = await self._get("/services/server/info", params={"output_mode": "json"})
        self.capabilities = {"saved_searches": await self._probe("/services/saved/searches"),
                             "correlation_searches": True, "notable_events": True}
        ver = ""
        if info and info.get("entry"):
            ver = info["entry"][0].get("content", {}).get("version", "")
        return {"api_version": ver or self.api_version or "unknown", "deployment": "Splunk Enterprise Security",
                "capabilities": self.capabilities}

    async def _probe(self, path: str) -> bool:
        try:
            r = await self.client().get(self.base + path, params={"output_mode": "json", "count": 1})
            return r.status_code < 400
        except httpx.HTTPError:
            return False

    async def get_rules(self, limit: int = 5000) -> list[dict]:
        data = await self._get("/services/saved/searches", params={"output_mode": "json", "count": limit,
                                                                   "search": "action.correlationsearch.enabled=1"})
        if not data:
            data = await self._get("/services/saved/searches", params={"output_mode": "json", "count": limit})
        return (data or {}).get("entry", [])

    async def get_log_sources(self) -> list[dict]:
        # Approximate from indexes
        data = await self._get("/services/data/indexes", params={"output_mode": "json", "count": 200})
        out = []
        for e in (data or {}).get("entry", []):
            c = e.get("content", {})
            out.append({"id": e.get("name"), "source_name": e.get("name"), "source_type": "application",
                        "collection_status": "active", "health_status": "healthy",
                        "event_volume": c.get("totalEventCount", 0), "last_event": None})
        return out

    async def get_offenses(self, limit: int = 2000) -> list[dict]:
        return []  # notable events require a search job; out of scope for this read-only metadata broker

    async def get_alerts(self) -> list[dict]:
        return []


# ------------------------------- Microsoft Sentinel -------------------------------
class SentinelAdapter(BaseAdapter):
    platform = "sentinel"
    # For Sentinel the 'host' is treated as the ARM resource path and secret is a bearer token.
    def _headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "Authorization": f"Bearer {self.secret}"}

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.base = "https://management.azure.com"
        self.resource = self.host  # e.g. subscriptions/.../resourceGroups/.../workspaces/<ws>

    async def connect(self) -> dict:
        self.capabilities = {"analytics_rules": True, "incidents": True, "data_connectors": True}
        return {"api_version": "2023-02-01", "deployment": "Microsoft Sentinel", "capabilities": self.capabilities}

    async def get_rules(self, limit: int = 5000) -> list[dict]:
        path = f"/{self.resource}/providers/Microsoft.SecurityInsights/alertRules"
        data = await self._get(path, params={"api-version": "2023-02-01"})
        return (data or {}).get("value", [])[:limit]

    async def get_log_sources(self) -> list[dict]:
        path = f"/{self.resource}/providers/Microsoft.SecurityInsights/dataConnectors"
        data = await self._get(path, params={"api-version": "2023-02-01"})
        out = []
        for c in (data or {}).get("value", []):
            out.append({"id": c.get("name"), "source_name": c.get("kind", "connector"),
                        "source_type": "cloud_audit", "collection_status": "active", "health_status": "healthy"})
        return out

    async def get_offenses(self, limit: int = 2000) -> list[dict]:
        path = f"/{self.resource}/providers/Microsoft.SecurityInsights/incidents"
        data = await self._get(path, params={"api-version": "2023-02-01", "$top": min(limit, 200)})
        out = []
        for i in (data or {}).get("value", []):
            p = i.get("properties", {})
            out.append({"id": i.get("name"), "description": p.get("title", ""), "severity": p.get("severity", "Medium"),
                        "status": p.get("status", "New"), "event_count": p.get("additionalData", {}).get("alertsCount", 0),
                        "first_seen": p.get("createdTimeUtc"), "last_seen": p.get("lastModifiedTimeUtc"), "rule_ids": []})
        return out

    async def get_alerts(self) -> list[dict]:
        return []


# ------------------------------- Elastic Security -------------------------------
class ElasticAdapter(BaseAdapter):
    platform = "elastic"
    def _headers(self) -> dict[str, str]:
        # Kibana API key
        return {"Accept": "application/json", "kbn-xsrf": "true", "Authorization": f"ApiKey {self.secret}"}

    async def connect(self) -> dict:
        status = await self._get("/api/status")
        self.capabilities = {"detection_rules": await self._probe("/api/detection_engine/rules/_find"),
                             "alerts": True}
        ver = ""
        if status:
            ver = (status.get("version") or {}).get("number", "")
        return {"api_version": ver or self.api_version or "unknown", "deployment": "Elastic Security",
                "capabilities": self.capabilities}

    async def _probe(self, path: str) -> bool:
        try:
            r = await self.client().get(self.base + path, params={"per_page": 1, "page": 1})
            return r.status_code < 400
        except httpx.HTTPError:
            return False

    async def get_rules(self, limit: int = 5000) -> list[dict]:
        out: list[dict] = []
        page = 1
        while len(out) < limit:
            data = await self._get("/api/detection_engine/rules/_find", params={"per_page": 100, "page": page})
            if not data:
                break
            items = data.get("data", [])
            out.extend(items)
            if len(items) < 100:
                break
            page += 1
        return out[:limit]

    async def get_log_sources(self) -> list[dict]:
        return []

    async def get_offenses(self, limit: int = 2000) -> list[dict]:
        return []

    async def get_alerts(self) -> list[dict]:
        return []


ADAPTERS = {"qradar": QRadarAdapter, "splunk": SplunkAdapter, "sentinel": SentinelAdapter, "elastic": ElasticAdapter}

def get_adapter(platform: str, host: str, port: int, secret: str, **kw) -> BaseAdapter:
    cls = ADAPTERS.get(platform)
    if not cls:
        raise SiemError(f"unsupported platform: {platform}")
    return cls(host, port, secret, **kw)
