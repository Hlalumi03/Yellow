import hmac
from collections.abc import Generator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.application.services import StoreService
from backend.config import Settings, get_settings
from backend.domain.entities import User
from backend.infrastructure.database import get_session
from backend.infrastructure.repositories import SqlAlchemyStoreRepository
from backend.infrastructure.sessions import get_session_record


def get_store_service(session: Session = Depends(get_session)) -> Generator[StoreService, None, None]:
    yield StoreService(SqlAlchemyStoreRepository(session))


def get_current_user(
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> User:
    token = request.cookies.get(settings.session_cookie_name, "")
    session_record = get_session_record(session, token)
    user = StoreService(SqlAlchemyStoreRepository(session)).get_user(session_record.user_id) if session_record and session_record.user_id else None
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    request.state.csrf_token = session_record.csrf_token
    return user


def get_customer(user: User = Depends(get_current_user)) -> User:
    if user.role.value != "customer":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Customer access required.")
    return user


def require_csrf(request: Request, user: User = Depends(get_current_user)) -> User:
    submitted = request.headers.get("X-CSRF-Token", "")
    expected = getattr(request.state, "csrf_token", "")
    if not submitted or not hmac.compare_digest(submitted, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token is invalid.")
    return user


def require_form_csrf(request: Request, submitted: str) -> None:
    expected = getattr(request.state, "csrf_token", "")
    if not submitted or not hmac.compare_digest(submitted, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This form has expired. Reload and try again.")
