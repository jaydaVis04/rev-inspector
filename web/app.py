from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from revinspector.analyzer import analyze_file  # noqa: E402


app = FastAPI(title="Rev Inspector")

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = PROJECT_ROOT / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
RECENT_ANALYSES: list[dict[str, object]] = []

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
            "recent_analyses": RECENT_ANALYSES,
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, file: UploadFile = File(...)):
    try:
        safe_name, saved_path = _save_upload(file)
    except ValueError as exc:
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "error": str(exc),
                "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
                "recent_analyses": RECENT_ANALYSES,
            },
            status_code=413,
        )

    report = analyze_file(saved_path)
    analyzed_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    _record_recent(safe_name, report, analyzed_at)

    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "filename": safe_name,
            "report": report,
            "analyzed_at": analyzed_at,
        },
    )


def _save_upload(file: UploadFile) -> tuple[str, Path]:
    original_name = Path(file.filename or "sample.bin").name
    safe_name = _safe_filename(original_name)
    saved_path = UPLOAD_DIR / f"{uuid4().hex}_{safe_name}"
    total = 0

    with saved_path.open("wb") as buffer:
        while chunk := file.file.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                buffer.close()
                saved_path.unlink(missing_ok=True)
                raise ValueError(f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB local analysis limit.")
            buffer.write(chunk)

    file.file.close()
    return safe_name, saved_path


def _safe_filename(filename: str) -> str:
    safe = Path(filename).name.strip().replace(" ", "_")
    safe = "".join(char for char in safe if char.isalnum() or char in {".", "_", "-"})
    return safe or "sample.bin"


def _record_recent(filename: str, report: dict[str, object], analyzed_at: str) -> None:
    RECENT_ANALYSES.insert(
        0,
        {
            "filename": filename,
            "analyzed_at": analyzed_at,
            "risk": str(report.get("risk", "low")).upper(),
            "indicator_count": len(report.get("findings", [])),
        },
    )
    del RECENT_ANALYSES[8:]
