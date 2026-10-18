# Log Analyzer - public, self-hosted version.
#
# PUBLIC VERSION: this file is a lighter copy of the hosted site's main.py.
# Removed: admin panel, visit statistics, feedback storage, "What's new" posts,
# database and proxy settings. Log analysis itself happens entirely in the
# browser (see src/), so the server here only serves pages and static files.

from pathlib import Path
import threading
import webbrowser

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

BASE_DIR = Path(__file__).parent

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# docs_url / redoc_url / openapi_url = None: the app has no public API,
# so the automatic API documentation pages are turned off.
app = FastAPI(
    title="Log Analyzer",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Security headers sent with every response.
# The Content-Security-Policy allows scripts, styles and connections only from
# this same server ('self'), so a log file with malicious content cannot load
# outside scripts. Trusted Types allow HTML to be built only through the
# narrow "xml-parser" policy used by the Windows XML parser.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
        "require-trusted-types-for 'script'; trusted-types xml-parser"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)

    return response


app.mount("/scriptsJS", StaticFiles(directory=BASE_DIR / "scriptsJS"), name="scriptsJS")
app.mount("/styles", StaticFiles(directory=BASE_DIR / "styles"), name="styles")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/")
async def root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/about")
async def about(request: Request):
    return templates.TemplateResponse(request=request, name="about.html")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(BASE_DIR / "static" / "favicon.svg", media_type="image/svg+xml")


@app.exception_handler(StarletteHTTPException)
async def http_error_page(request: Request, exc: StarletteHTTPException):
    # Browsers get a friendly 404 page; other clients get the normal JSON error.
    wants_html = "text/html" in request.headers.get("accept", "")
    if exc.status_code == 404 and wants_html:
        return templates.TemplateResponse(request=request, name="404.html", status_code=404)

    return await http_exception_handler(request, exc)


def open_browser():
    webbrowser.open("http://127.0.0.1:8000")


if __name__ == "__main__":
    # Open the browser one second after start, when the server is ready.
    threading.Timer(1, open_browser).start()

    # host="127.0.0.1": the app is reachable only from this computer.
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True, server_header=False)
