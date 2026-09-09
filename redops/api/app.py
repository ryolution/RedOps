"""Serve existing assessment data; no target scanning, uploads, or command execution."""

import getpass
import hmac
import os
from collections.abc import Callable
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError

from redops.core.audit import AuditLog
from redops.core.config import Settings
from redops.core.errors import AssessmentNotFound, InputError, RedOpsError, ReviewConflict
from redops.core.io import require_distinct_paths
from redops.database.repository import Repository
from redops.database.reviews import add_review, list_reviews
from redops.reporting.render import render_report


class ReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    disposition: Literal["needs_review", "affected", "not_affected", "accepted_risk", "remediated"]
    notes: str = Field(max_length=10000)
    expected_previous: int = Field(ge=0)


def create_app(settings: Settings | None = None, *, token: str | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    token = token if token is not None else os.environ.get("REDOPS_API_TOKEN", "")
    if len(token) < 32 or len(token) > 4096:
        raise RedOpsError("REDOPS_API_TOKEN must contain between 32 and 4096 characters.")
    require_distinct_paths(settings.storage_paths())
    audit = AuditLog(settings.audit_path)
    operator = os.environ.get("REDOPS_OPERATOR", getpass.getuser()).strip()
    if not operator or len(operator) > 200 or "\x00" in operator:
        raise RedOpsError("REDOPS_OPERATOR must be a nonempty name of at most 200 characters.")
    bearer = HTTPBearer(auto_error=False)
    app = FastAPI(title="RedOps", version="", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    def authenticate(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> None:
        valid = (
            credentials is not None
            and len(credentials.credentials) <= 4096
            and hmac.compare_digest(credentials.credentials.encode("utf-8"), token.encode("utf-8"))
        )
        if not valid:
            try:
                audit.record("api_auth", "denied", operator="api")
            except OSError as exc:
                raise HTTPException(503, "Audit storage is unavailable.") from exc
            raise HTTPException(
                401, "Authentication required.", headers={"WWW-Authenticate": "Bearer"}
            )

    def read(action: str, callback: Callable[[Repository], Any]) -> Any:
        def record(status: str) -> None:
            try:
                audit.record(action, status, operator="api")
            except OSError as exc:
                raise HTTPException(503, "Audit storage is unavailable.") from exc

        repository = None
        try:
            record("started")
            repository = Repository(settings.database_url)
            result = callback(repository)
            record("completed")
            return result
        except AssessmentNotFound as exc:
            record("not_found")
            raise HTTPException(404, "Assessment not found.") from exc
        except InputError as exc:
            record("rejected")
            raise HTTPException(422, str(exc)) from exc
        except (SQLAlchemyError, RedOpsError, OSError) as exc:
            record("failed")
            raise HTTPException(503, "Assessment or audit storage is unavailable.") from exc
        finally:
            if repository is not None:
                repository.close()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "RedOps"}

    def review_operation(callback: Callable[[], Any]) -> Any:
        try:
            return callback()
        except ReviewConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except AssessmentNotFound as exc:
            raise HTTPException(404, "Assessment or finding not found.") from exc
        except InputError as exc:
            raise HTTPException(422, str(exc)) from exc
        except (SQLAlchemyError, RedOpsError, OSError) as exc:
            raise HTTPException(
                503, "Review or audit storage is unavailable; check schema migration."
            ) from exc

    @app.get(
        "/assessments/{assessment_id}/findings/{key}/reviews", dependencies=[Depends(authenticate)]
    )
    def history(
        assessment_id: UUID,
        key: str,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0, le=1000000)] = 0,
    ) -> dict[str, Any]:
        return review_operation(
            lambda: list_reviews(settings, str(assessment_id), key, limit=limit, offset=offset)
        )

    @app.post(
        "/assessments/{assessment_id}/findings/{key}/reviews",
        dependencies=[Depends(authenticate)],
        status_code=201,
    )
    def review(assessment_id: UUID, key: str, body: ReviewInput) -> dict[str, Any]:
        return review_operation(
            lambda: add_review(
                settings, str(assessment_id), key, **body.model_dump(), operator=operator
            )
        )

    @app.get("/ready", dependencies=[Depends(authenticate)])
    def ready() -> dict[str, str]:
        read("api_ready", lambda repository: repository.list_assessments(limit=1))
        return {"status": "ready"}

    @app.get("/assessments", dependencies=[Depends(authenticate)])
    def assessments(
        engagement: Annotated[str | None, Query(max_length=200)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0, le=1000000)] = 0,
    ) -> dict[str, Any]:
        records = read(
            "api_list",
            lambda repository: repository.list_assessments(
                engagement=engagement,
                limit=limit,
                offset=offset,
            ),
        )
        return {"items": records, "limit": limit, "offset": offset}

    @app.get("/assessments/{assessment_id}", dependencies=[Depends(authenticate)])
    def assessment(assessment_id: UUID) -> dict[str, Any]:
        return read("api_assessment", lambda repository: repository.get(str(assessment_id)))

    @app.get("/assessments/{assessment_id}/inventory", dependencies=[Depends(authenticate)])
    def inventory(assessment_id: UUID) -> list[dict[str, Any]]:
        return read("api_inventory", lambda repository: repository.inventory(str(assessment_id)))

    @app.get("/assessments/{assessment_id}/report", dependencies=[Depends(authenticate)])
    def report(assessment_id: UUID, format: Literal["json", "html", "pdf"] = "json") -> Response:
        content = read(
            "api_report",
            lambda repository: render_report(repository.get(str(assessment_id)), format),
        )
        media_type = {"json": "application/json", "html": "text/html", "pdf": "application/pdf"}[
            format
        ]
        return Response(
            content,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="redops-{assessment_id}.{format}"',
            },
        )

    return app
