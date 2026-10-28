import hashlib
import secrets
import time

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.infrastructure.models import SessionModel


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()


def get_session_record(session: Session, token: str) -> SessionModel | None:
    if not token:
        return None
    return session.scalar(select(SessionModel).where(
        SessionModel.token_hash == hash_token(token),
        SessionModel.expires_at > int(time.time()),
    ))


def create_session(session: Session, user_id: str | None, lifetime: int) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    session.execute(delete(SessionModel).where(SessionModel.expires_at <= int(time.time())))
    session.add(SessionModel(
        token_hash=hash_token(token), csrf_token=csrf_token, user_id=user_id,
        expires_at=int(time.time()) + lifetime,
    ))
    session.commit()
    return token, csrf_token


def delete_session(session: Session, token: str) -> None:
    session.execute(delete(SessionModel).where(SessionModel.token_hash == hash_token(token)))
    session.commit()


def replace_session(session: Session, token: str, user_id: str, lifetime: int) -> tuple[str, str]:
    new_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    session.execute(delete(SessionModel).where(SessionModel.token_hash == hash_token(token)))
    session.execute(delete(SessionModel).where(SessionModel.expires_at <= int(time.time())))
    session.add(SessionModel(
        token_hash=hash_token(new_token), csrf_token=csrf_token, user_id=user_id,
        expires_at=int(time.time()) + lifetime,
    ))
    session.commit()
    return new_token, csrf_token
