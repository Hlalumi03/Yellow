from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import PROJECT_ROOT, get_settings
from backend.domain.errors import ConflictError, DomainError, NotFoundError
from backend.presentation.api import router as api_router
from backend.presentation.web import router as web_router


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name, version="1.0.0",
        docs_url="/api/docs", redoc_url="/api/redoc", openapi_url="/api/openapi.json",
    )
    if settings.allowed_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token"],
        )
    application.mount("/static", StaticFiles(directory=str(PROJECT_ROOT / "frontend")), name="static")
    application.include_router(api_router)
    application.include_router(web_router)

    @application.exception_handler(DomainError)
    async def domain_error_handler(_request: Request, error: DomainError):
        if isinstance(error, NotFoundError):
            code = 404
        elif isinstance(error, ConflictError):
            code = 409
        else:
            code = 400
        return JSONResponse(status_code=code, content={"detail": error.message, "code": error.code})

    @application.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' https://images.unsplash.com data:; "
            "style-src 'self' https://cdn.jsdelivr.net; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        return response

    @application.get("/healthz", tags=["system"])
    def healthcheck():
        return {"status": "ok"}

    return application


app = create_app()
