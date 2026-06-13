from pathlib import Path
from tempfile import NamedTemporaryFile

from revinspector.cli import main
from revinspector.report import analyze_file

try:
    from fastapi import FastAPI, File, UploadFile
except ImportError:
    FastAPI = None
    File = None
    UploadFile = None


if FastAPI is not None:
    app = FastAPI(title="Rev Inspector", description="Static analysis only. Uploaded files are not executed.")

    @app.get("/")
    async def index():
        return {
            "name": "Rev Inspector",
            "scope": "static analysis only",
            "upload_endpoint": "/analyze",
            "docs": "/docs",
        }

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/analyze")
    async def analyze_upload(sample: UploadFile = File(...)):
        suffix = Path(sample.filename or "sample.bin").suffix
        with NamedTemporaryFile(suffix=suffix) as handle:
            handle.write(await sample.read())
            handle.flush()
            report = analyze_file(Path(handle.name))
        data = report.to_dict()
        data["uploaded_filename"] = sample.filename
        return data


if __name__ == "__main__":
    raise SystemExit(main())
