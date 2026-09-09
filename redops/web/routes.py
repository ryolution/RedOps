"""Server-rendered evidence dashboard; browser writes are limited to review annotations."""

import hmac
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from redops.core.audit import AuditLog
from redops.core.config import Settings
from redops.core.errors import AssessmentNotFound, InputError, RedOpsError, ReviewConflict
from redops.core.reviews import DISPOSITIONS
from redops.database.repository import Repository
from redops.database.reviews import add_review, list_reviews
from redops.reporting.document import report_document
from redops.reporting.render import render_report
from redops.web.sessions import Sessions

ROOT = Path(__file__).resolve().parent
COOKIE = "redops_session"
LABELS = {
    "needs_review": "Needs review",
    "affected": "Affected",
    "not_affected": "Not affected",
    "accepted_risk": "Accepted risk",
    "remediated": "Remediated",
}


class LoginRequired(Exception):
    pass


def install_dashboard(
    app: FastAPI, settings: Settings, token: str, operator: str, *, allow_http: bool = False
) -> None:
    templates = Jinja2Templates(directory=str(ROOT / "templates"))
    sessions, audit = Sessions(), AuditLog(settings.audit_path)
    app.state.browser_sessions = sessions
    router = APIRouter(prefix="/ui", include_in_schema=False)
    app.mount("/ui/static", StaticFiles(directory=str(ROOT / "static")), name="ui_static")

    def transport(request: Request) -> None:
        local = allow_http and request.url.hostname in {"localhost", "127.0.0.1", "::1"}
        if request.url.scheme != "https" and not local:
            raise HTTPException(
                400, "The dashboard requires HTTPS outside explicit loopback development."
            )

    def session(request: Request, *, authenticated: bool = True):
        transport(request)
        result = sessions.get(request.cookies.get(COOKIE, ""))
        if result is None or (authenticated and not result.authenticated):
            raise LoginRequired
        return result

    def render(request: Request, name: str, *, status: int = 200, **context: Any):
        current = sessions.get(request.cookies.get(COOKIE, ""))
        return templates.TemplateResponse(
            request=request,
            name=name,
            status_code=status,
            context={
                "operator": operator,
                "session": current,
                "labels": LABELS,
                **context,
            },
        )

    def error(request: Request, status: int, message: str, **context: Any):
        return render(
            request, "error.html", status=status, error_status=status, message=message, **context
        )

    def guard(endpoint):
        @wraps(endpoint)
        async def wrapped(*args, **kwargs):
            request = kwargs["request"]
            try:
                return await endpoint(*args, **kwargs)
            except LoginRequired:
                suffix = "?expired=1" if request.cookies.get(COOKIE) else ""
                return RedirectResponse("/ui/login" + suffix, status_code=303)
            except ReviewConflict as exc:
                return error(request, 409, str(exc))
            except AssessmentNotFound:
                return error(request, 404, "The assessment or finding could not be found.")
            except InputError as exc:
                return error(request, 422, str(exc))
            except HTTPException as exc:
                return error(request, exc.status_code, str(exc.detail))
            except RedOpsError as exc:
                return error(request, 503, str(exc))
            except (SQLAlchemyError, OSError):
                return error(
                    request,
                    503,
                    "Assessment or audit storage is unavailable. "
                    "Check storage and schema readiness.",
                )

        return wrapped

    async def form(request: Request, fields: set[str]) -> dict[str, str]:
        if (
            request.headers.get("content-type", "").split(";")[0]
            != "application/x-www-form-urlencoded"
        ):
            raise HTTPException(415, "Use the dashboard form to submit this request.")
        content = bytearray()
        async for chunk in request.stream():
            if len(content) + len(chunk) > 64 * 1024:
                raise HTTPException(413, "The submitted form exceeds 64 KiB.")
            content.extend(chunk)
        try:
            values = parse_qs(
                content.decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=8,
            )
        except (ValueError, UnicodeError) as exc:
            raise InputError("Invalid form encoding.") from exc
        if set(values) != fields or any(len(value) != 1 for value in values.values()):
            raise InputError("Invalid or duplicate form fields.")
        return {key: value[0] for key, value in values.items()}

    def csrf(request: Request, values: dict[str, str], current) -> None:
        origin = request.headers.get("origin")
        expected_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
        valid_origin = origin is None or origin == expected_origin
        if (
            not valid_origin
            or request.headers.get("sec-fetch-site") == "cross-site"
            or not hmac.compare_digest(values.get("csrf", "").encode(), current.csrf.encode())
        ):
            audit.record("ui_csrf", "denied", operator=operator)
            raise HTTPException(
                403, "The form could not be verified. Reload the page and try again."
            )

    def read(callback):
        audit.record("ui_read", "started", operator=operator)
        repository = None
        try:
            repository = Repository(settings.database_url)
            result = callback(repository)
            audit.record("ui_read", "completed", operator=operator)
            return result
        except Exception as exc:
            audit.record("ui_read", "failed", operator=operator, error_type=type(exc).__name__)
            raise
        finally:
            if repository is not None:
                repository.close()

    def identifier(value: str) -> str:
        try:
            return str(UUID(value))
        except ValueError as exc:
            raise InputError("Invalid assessment identifier.") from exc

    def page_number(request: Request, field: str = "page") -> int:
        try:
            result = int(request.query_params.get(field, "1"))
            if not 1 <= result <= 40000:
                raise ValueError
            return result
        except ValueError as exc:
            raise InputError("Page number must be between 1 and 40000.") from exc

    def query(request: Request, field: str) -> str:
        value = request.query_params.get(field, "")
        if len(value) > 200:
            raise InputError("Search and filter values are limited to 200 characters.")
        return value

    def pager(request: Request, number: int, more: bool, field: str = "page") -> dict:
        values = dict(request.query_params)
        return {
            "number": number,
            "previous": "?" + urlencode({**values, field: number - 1}) if number > 1 else None,
            "next": "?" + urlencode({**values, field: number + 1}) if more else None,
        }

    @router.get("/login", name="ui_login")
    @guard
    async def login_page(request: Request):
        transport(request)
        current = sessions.get(request.cookies.get(COOKIE, ""))
        if current and current.authenticated:
            return RedirectResponse("/ui", status_code=303)
        cookie, current = sessions.create()
        response = render(
            request,
            "login.html",
            csrf=current.csrf,
            expired=request.query_params.get("expired") == "1",
        )
        response.set_cookie(
            COOKIE,
            cookie,
            max_age=1800,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/ui",
        )
        return response

    @router.post("/login")
    @guard
    async def login(request: Request):
        current = session(request, authenticated=False)
        values = await form(request, {"csrf", "token"})
        csrf(request, values, current)
        address = request.client.host if request.client else "unknown"
        if sessions.throttled(address):
            audit.record("ui_login", "throttled", operator=operator)
            response = error(
                request, 429, "Too many unsuccessful sign-in attempts. Try again in one minute."
            )
            response.headers["Retry-After"] = "60"
            return response
        if len(values["token"]) > 4096 or not hmac.compare_digest(
            values["token"].encode(), token.encode()
        ):
            sessions.failed(address)
            audit.record("ui_login", "denied", operator=operator)
            return render(
                request,
                "login.html",
                status=401,
                csrf=current.csrf,
                login_error="The token was not accepted.",
            )
        audit.record("ui_login", "completed", operator=operator)
        sessions.remove(request.cookies.get(COOKIE, ""))
        cookie, _ = sessions.create(authenticated=True)
        response = RedirectResponse("/ui", status_code=303)
        response.set_cookie(
            COOKIE,
            cookie,
            max_age=1800,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/ui",
        )
        return response

    @router.post("/logout", name="ui_logout")
    @guard
    async def logout(request: Request):
        current = session(request)
        csrf(request, await form(request, {"csrf"}), current)
        audit.record("ui_logout", "completed", operator=operator)
        sessions.remove(request.cookies.get(COOKIE, ""))
        response = RedirectResponse("/ui/login", status_code=303)
        response.delete_cookie(
            COOKIE,
            path="/ui",
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
        )
        return response

    @router.get("", name="ui_home")
    @guard
    async def home(request: Request):
        session(request)
        number, engagement = page_number(request), query(request, "engagement")
        records = await run_in_threadpool(
            read,
            lambda repository: repository.list_assessments(
                engagement=engagement or None, limit=26, offset=(number - 1) * 25
            ),
        )
        return render(
            request,
            "history.html",
            records=records[:25],
            engagement=engagement,
            pagination=pager(request, number, len(records) > 25),
        )

    @router.get("/assessments/{assessment_id}", name="ui_assessment")
    @guard
    async def assessment_page(request: Request, assessment_id: str):
        session(request)
        assessment_id = identifier(assessment_id)
        snapshot = await run_in_threadpool(list_reviews, settings, assessment_id)
        document = snapshot["assessment"]
        search, severity, disposition = (
            query(request, field) for field in ("q", "severity", "disposition")
        )
        if severity not in {
            "",
            "critical",
            "high",
            "medium",
            "low",
            "none",
            "unknown",
        } or disposition not in ("", *DISPOSITIONS):
            raise InputError("Invalid finding filter.")
        rows = []
        for host in document["hosts"]:
            for service in host["services"] or [None]:
                row = {"host": host, "service": service}
                haystack = " ".join(
                    str(value)
                    for value in [
                        host["ip"],
                        host["hostname"],
                        host["os"],
                        *(
                            (service or {}).get(key, "")
                            for key in ("name", "product", "version", "port")
                        ),
                    ]
                )
                if search.lower() in haystack.lower():
                    rows.append(row)
        findings = [
            item
            for item in snapshot["findings"]
            if (not severity or item["severity"] == severity)
            and (
                not disposition
                or (item["review"] or {}).get("disposition", "needs_review") == disposition
            )
            and search.lower()
            in " ".join(
                str(item[field]) for field in ("host", "port", "vulnerability_id", "description")
            ).lower()
        ]
        inventory_page, findings_page = (
            page_number(request, "inventory_page"),
            page_number(request, "findings_page"),
        )
        return render(
            request,
            "assessment.html",
            document=document,
            snapshot=snapshot,
            inventory=rows[(inventory_page - 1) * 25 : inventory_page * 25],
            inventory_total=len(rows),
            findings=findings[(findings_page - 1) * 25 : findings_page * 25],
            findings_total=len(findings),
            inventory_pager=pager(
                request, inventory_page, len(rows) > inventory_page * 25, "inventory_page"
            ),
            findings_pager=pager(
                request, findings_page, len(findings) > findings_page * 25, "findings_page"
            ),
            search=search,
            severity=severity,
            disposition=disposition,
        )

    @router.get("/assessments/{assessment_id}/findings/{key}", name="ui_finding")
    @guard
    async def finding_page(request: Request, assessment_id: str, key: str):
        session(request)
        assessment_id, number = identifier(assessment_id), page_number(request)
        snapshot = await run_in_threadpool(list_reviews, settings, assessment_id)
        finding = next((item for item in snapshot["findings"] if item["key"] == key), None)
        if finding is None:
            raise AssessmentNotFound
        history = await run_in_threadpool(
            list_reviews, settings, assessment_id, key, limit=26, offset=(number - 1) * 25
        )
        source = urlsplit(finding["source"])
        source_url = (
            finding["source"]
            if source.scheme == "https"
            and source.hostname
            and not source.username
            and not source.password
            else None
        )
        return render(
            request,
            "finding.html",
            document=snapshot["assessment"],
            finding=finding,
            history=history,
            events=history["items"][:25],
            source_url=source_url,
            pagination=pager(request, number, len(history["items"]) > 25),
        )

    @router.post("/assessments/{assessment_id}/findings/{key}/reviews", name="ui_review")
    @guard
    async def submit_review(request: Request, assessment_id: str, key: str):
        current = session(request)
        assessment_id = identifier(assessment_id)
        values = await form(request, {"csrf", "disposition", "notes", "expected_previous"})
        csrf(request, values, current)
        try:
            expected = int(values["expected_previous"])
        except ValueError as exc:
            raise InputError("Invalid expected review identifier.") from exc
        try:
            await run_in_threadpool(
                add_review,
                settings,
                assessment_id,
                key,
                disposition=values["disposition"],
                notes=values["notes"],
                expected_previous=expected,
                operator=operator,
            )
        except ReviewConflict as exc:
            return error(
                request,
                409,
                str(exc),
                unsaved_notes=values["notes"],
                return_to=f"/ui/assessments/{assessment_id}/findings/{key}",
            )
        return RedirectResponse(f"/ui/assessments/{assessment_id}/findings/{key}", status_code=303)

    @router.get("/assessments/{assessment_id}/report", name="ui_report")
    @guard
    async def download(request: Request, assessment_id: str):
        session(request)
        assessment_id = identifier(assessment_id)
        format_name = request.query_params.get("format", "pdf")
        if format_name not in {"json", "html", "pdf"}:
            raise InputError("Unsupported report format.")
        include_reviews = request.query_params.get("include_reviews", "false")
        if include_reviews not in {"true", "false"}:
            raise InputError("Review inclusion must be true or false.")
        content = await run_in_threadpool(
            read,
            lambda repository: render_report(
                report_document(
                    repository, assessment_id, include_reviews=include_reviews == "true"
                ),
                format_name,
            ),
        )
        return Response(
            content,
            media_type={"json": "application/json", "html": "text/html", "pdf": "application/pdf"}[
                format_name
            ],
            headers={
                "Content-Disposition": (
                    f'attachment; filename="redops-{assessment_id}.{format_name}"'
                )
            },
        )

    app.include_router(router)
