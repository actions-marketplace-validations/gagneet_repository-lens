"""A single-repository local API; it is not a multi-tenant hosted scanning service."""
from __future__ import annotations

import json
from pathlib import Path
import secrets
import threading
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..analysis import MAX_VIEW_DEPTH, VIEW_DEPTH, Analysis, LIMITS, analyze
from ..core.findings import to_sarif
from ..provenance import tool_build
from ..impact.config import Config
from ..impact.render import render_json, render_mermaid


class ScanRequest(BaseModel):
    """Optional file size and file count limits for a scan; no other options are accepted."""

    model_config = ConfigDict(extra="forbid")
    max_file_bytes: int = Field(default=2_000_000, ge=1, le=2_000_000, description="Maximum source bytes per file.")
    max_files: int = Field(default=10_000, ge=1, le=10_000, description="Maximum admitted files; truncation is reported as incomplete.")


class ImpactRequest(BaseModel):
    """A search over the latest scan and how far to follow relationships from its matches."""

    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=500, examples=["list_items"])
    max_nodes: int = Field(default=30, ge=1, le=100)
    depth: int = Field(default=VIEW_DEPTH, ge=1, le=MAX_VIEW_DEPTH, description="Relationship hops from the matched nodes. A table to page chain is typically 5-6 hops.")


class NodeRecord(BaseModel):
    """One code element found in the repository, such as a file, function, route or table."""

    id: str
    kind: str
    label: str
    path: str | None = None
    line: int | None = None
    language: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class EdgeRecord(BaseModel):
    """A relationship between two nodes, with the evidence it was inferred from."""

    source: str
    target: str
    kind: str
    resolution: str = Field(description="Evidence strength, not proof of runtime execution.")
    evidence: str
    origin: str
    direct: bool
    activation: str
    detail: str | None = None


class Diagnostic(BaseModel):
    """A problem or limitation noticed while building the graph, with a recommendation."""

    code: str
    severity: str
    message: str
    node_ids: list[str]
    evidence: str
    recommendation: str
    subject: str = ""


class GraphRecord(BaseModel):
    """The full relationship graph of the scanned repository."""

    version: int
    root: str
    metadata: dict[str, Any]
    nodes: list[NodeRecord]
    edges: list[EdgeRecord]
    issues: list[Diagnostic]


class ToolStatus(BaseModel):
    """Whether one analysis tool ran, failed or was skipped, and how many findings it made."""

    tool: str
    error: str
    skipped: str
    finding_count: int
    notes: list[str] = Field(default_factory=list, description="Inputs this tool never examined; its results do not cover them.")


class FindingRecord(BaseModel):
    """One prioritised finding at a file and line, with its evidence and suggested remedy."""

    model_config = ConfigDict(extra="allow")
    tool: str
    rule: str
    severity: str
    confidence: str
    category: str
    file: str
    line: int
    message: str
    remedy: str
    evidence: str
    priority: str
    fingerprint: str


class AnalysisResponse(BaseModel):
    """The result of a scan: its graph, tool statuses, findings and stated limits."""

    schema_version: str
    tool_version: str
    complete: bool = Field(description="Supported checks completed; does not mean vulnerability-free or fully understood.")
    scope: str
    limits: list[str]
    coverage: dict[str, int]
    graph: GraphRecord
    tools: list[ToolStatus]
    findings: list[FindingRecord]
    incomplete_reasons: list[str] = Field(default_factory=list, description="One line per cause when `complete` is false.")
    tool_build: dict[str, Any] = Field(default_factory=dict, description="The repolens build that produced this result.")
    config_sha256: str = Field(default="", description="Fingerprint of the scanner settings and version.")


class MatchRecord(BaseModel):
    """A node that matched the query, with its score and why it matched."""

    node_id: str
    score: float
    reasons: list[str]
    snippets: list[str]


class ImpactResponse(BaseModel):
    """The bounded part of the graph connected to the query's matches, and what was left out."""

    query: str
    seeds: list[MatchRecord]
    nodes: list[NodeRecord]
    edges: list[EdgeRecord]
    issues: list[Diagnostic]
    classifications: dict[str, str]
    omitted_nodes: int
    omitted_breakdown: list[dict[str, Any]]


class HealthResponse(BaseModel):
    """Service liveness and version."""

    status: Literal["ok"]
    version: str


class CapabilitiesResponse(BaseModel):
    """The languages, frameworks and databases the analysis supports, and its limits."""

    languages: list[str]
    frameworks: list[str]
    databases: list[str]
    limits: list[str]


def create_app(root: Path, token: str) -> FastAPI:
    """The loopback-only API for the checkout at `root`, guarded by bearer `token`.

    `token` must be at least 32 characters. The latest analysis is held in process
    memory; requests can bound a scan but never choose a path, command or plugin."""
    tool_build()  # stamp the code this server loaded, before any checkout can change
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("repository root must be an existing directory")
    if len(token) < 32:
        raise ValueError("API token must contain at least 32 characters")
    app = FastAPI(
        title="Repository Lens API", version=__version__,
        description="Static analysis of one operator-configured local repository. Requests cannot select filesystem paths, run commands, load plugins, clone repositories or connect to databases. Results describe evidence and limitations.",
        openapi_tags=[{"name": "Status", "description": "Service status and analysis scope."},
                      {"name": "Analysis", "description": "Scan, inspect and export the configured repository."}],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "::1", "[::1]"])
    bearer = HTTPBearer(auto_error=False)
    latest: Analysis | None = None
    scanning = threading.Lock()

    def authorize(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
        if credentials is None or not secrets.compare_digest(credentials.credentials.encode("utf-8"), token.encode("utf-8")):
            raise HTTPException(401, "A valid bearer token is required.", headers={"WWW-Authenticate": "Bearer"})

    def current() -> Analysis:
        if latest is None or scanning.locked():
            raise HTTPException(409, "Run POST /v1/analysis before querying results.")
        return latest

    auth = [Depends(authorize)]
    errors = {401: {"description": "Missing or invalid bearer token."},
              409: {"description": "No completed scan, or another scan is in progress."},
              503: {"description": "Analysis dependencies unavailable or scan failed."}}

    @app.get("/health", response_model=HealthResponse, tags=["Status"], operation_id="health")
    def health():
        """Check service availability without disclosing repository details."""
        return {"status": "ok", "version": __version__}

    @app.get("/v1/capabilities", response_model=CapabilitiesResponse, dependencies=auth,
             tags=["Status"], operation_id="capabilities", responses=errors)
    def capabilities():
        """Read the implemented scope and its limitations."""
        return {"languages": ["python", "javascript", "typescript"], "frameworks": ["fastapi", "nextjs-app-router"],
                "databases": ["postgresql-static-sql"], "limits": LIMITS}

    @app.post("/v1/analysis", response_model=AnalysisResponse, dependencies=auth,
              tags=["Analysis"], operation_id="scan_repository", responses=errors)
    def scan(request: ScanRequest):
        """Scan the configured checkout. Incomplete results remain available with complete=false."""
        nonlocal latest
        if not scanning.acquire(blocking=False):
            raise HTTPException(409, "A scan is already in progress.")
        try:
            # Start with repository policy, then apply only the bounded request knobs.
            # The API never accepts a path, command, or plugin from the caller.
            settings = Config.load(root)
            settings.max_file_bytes = request.max_file_bytes
            settings.max_files = request.max_files
            settings.validate()
            result = analyze(root, config=settings)
            latest = result
            return result.to_dict()
        except Exception as exc:
            # Do not disclose paths, source text or exception payloads to API clients.
            raise HTTPException(503, "Analysis could not complete. Verify parser dependencies and local repository access.") from exc
        finally:
            scanning.release()

    @app.get("/v1/analysis", response_model=AnalysisResponse, dependencies=auth,
             tags=["Analysis"], operation_id="get_analysis", responses=errors)
    def get_analysis():
        """Read the most recent scan held in this process; restarting clears it."""
        return current().to_dict()

    @app.post("/v1/impact", response_model=ImpactResponse, dependencies=auth,
              tags=["Analysis"], operation_id="query_impact", responses=errors)
    def query_impact(request: ImpactRequest):
        """Query stored graph evidence without reading or executing target source."""
        return json.loads(render_json(current().view(request.query, request.max_nodes, request.depth)))

    @app.get("/v1/report", response_class=PlainTextResponse, dependencies=auth,
             tags=["Analysis"], operation_id="export_report", responses=errors)
    def export_report(format: Literal["markdown", "mermaid", "sarif", "html"] = "markdown",
                      query: str = Query(default="", max_length=500),
                      max_nodes: int = Query(default=30, ge=1, le=100),
                      depth: int = Query(default=VIEW_DEPTH, ge=1, le=MAX_VIEW_DEPTH)):
        """Export a bounded Mermaid/Markdown/HTML view or the full normalized SARIF findings."""
        analysis = current()
        if format == "html":
            return HTMLResponse(analysis.html(query, max_nodes, depth),
                                headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
        if format == "mermaid":
            return PlainTextResponse(render_mermaid(analysis.view(query, max_nodes, depth)))
        if format == "sarif":
            return PlainTextResponse(to_sarif(analysis.runs, __version__, build=tool_build()), media_type="application/sarif+json")
        return PlainTextResponse(analysis.markdown(query, max_nodes, depth), media_type="text/markdown")

    return app
