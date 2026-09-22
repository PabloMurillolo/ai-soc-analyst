import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from . import db
from .engine import RULES, detect
from .simulations import SCENARIOS, generate
from .investigation import investigate

load_dotenv()
STATIC = Path(__file__).parent / "static"

def now():
    return datetime.now(timezone.utc).isoformat()

class Simulation(BaseModel):
    scenario: Literal["password-guessing", "encoded-powershell", "cloud-exfiltration", "benign-activity"]

class Update(BaseModel):
    status: Literal["open", "investigating", "resolved"]
    note: str = Field(default="", max_length=2000)

class Question(BaseModel):
    question: str = Field(min_length=1, max_length=2000)

def run_simulation(path, scenario):
    run_id = str(uuid4())
    events = generate(scenario)
    findings = detect(events)
    ids = []
    with db.connect(path) as conn:
        conn.execute("INSERT INTO runs VALUES (?,?,?)", (run_id, scenario, now()))
        for event in events:
            conn.execute("INSERT INTO events VALUES (?,?,?,?)", (event["id"], run_id, event["timestamp"], json.dumps(event)))
        for rule, evidence in findings:
            iid = str(uuid4())
            ids.append(iid)
            conn.execute("INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?)", (iid,run_id,rule["id"],rule["name"],rule["severity"],"open",now(),evidence[0]["host"],evidence[0]["user"],json.dumps(evidence)))
            conn.execute("INSERT INTO audit(incident_id,created_at,action,note) VALUES (?,?,?,?)", (iid,now(),"detected",rule["description"]))
    return {"run_id":run_id, "events_created":len(events), "incidents_created":len(ids), "incident_ids":ids}

def create_app(database_path=None, seed=True):
    path = str(database_path or os.getenv("SOC_DB_PATH", "data/soc.db"))
    @asynccontextmanager
    async def lifespan(app):
        db.initialize(path)
        with db.connect(path) as conn:
            empty = conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 0
        if seed and empty:
            for scenario in SCENARIOS:
                run_simulation(path, scenario)
        yield
    app = FastAPI(title="AI SOC Analyst", version="0.1.0", lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])

    @app.middleware("http")
    async def boundaries(request: Request, call_next):
        if request.method in ("POST", "PATCH", "DELETE", "PUT"):
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                return JSONResponse({"detail":"Cross-origin writes are disabled"}, status_code=403)
            if request.headers.get("sec-fetch-site") == "cross-site":
                return JSONResponse({"detail":"Cross-site writes are disabled"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
        if request.url.path in ("/docs", "/redoc"):
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
        return response

    def get_incident(iid):
        with db.connect(path) as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
            if row is None:
                raise HTTPException(404, "Incident not found")
            result = db.incident(row)
            result["audit"] = [dict(r) for r in conn.execute("SELECT * FROM audit WHERE incident_id=? ORDER BY id", (iid,))]
        result["rule"] = next(r for r in RULES if r["id"] == result["rule_id"])
        return result

    @app.get("/api/health")
    def health():
        with db.connect(path) as conn:
            conn.execute("SELECT 1")
        return {"status":"ok", "version":"0.1.0", "synthetic":True, "ai_provider":os.getenv("AI_PROVIDER", "offline")}

    @app.get("/api/overview")
    def overview():
        with db.connect(path) as conn:
            incidents = [db.incident(r) for r in conn.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 500")]
            counts = dict(conn.execute("SELECT status,count(*) FROM incidents GROUP BY status").fetchall())
            total_events = conn.execute("SELECT count(*) FROM events").fetchone()[0]
            runs = [dict(r) for r in conn.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT 12")]
            critical = conn.execute("SELECT count(*) FROM incidents WHERE severity='critical' AND status!='resolved'").fetchone()[0]
            total = conn.execute("SELECT count(*) FROM incidents").fetchone()[0]
        return {"incidents":incidents,"counts":counts,"events":total_events,"runs":runs,"critical":critical,"total_incidents":total,"rules":RULES,"scenarios":SCENARIOS}

    @app.get("/api/incidents/{iid}")
    def detail(iid: str):
        return get_incident(iid)

    @app.patch("/api/incidents/{iid}")
    def update(iid: str, body: Update):
        get_incident(iid)
        with db.connect(path) as conn:
            conn.execute("UPDATE incidents SET status=? WHERE id=?", (body.status, iid))
            conn.execute("INSERT INTO audit(incident_id,created_at,action,note) VALUES (?,?,?,?)", (iid,now(),body.status,body.note.strip()))
        return get_incident(iid)

    @app.post("/api/simulations", status_code=201)
    def simulate(body: Simulation):
        return run_simulation(path, body.scenario)

    @app.post("/api/incidents/{iid}/investigate")
    async def investigation(iid: str, body: Question):
        item = get_incident(iid)
        try:
            return await investigate(item, item["rule"], body.question)
        except Exception:
            raise HTTPException(503, "Local AI is unavailable. Start Ollama or set AI_PROVIDER=offline.")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")
    return app

app = create_app()
