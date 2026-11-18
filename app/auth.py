import os
import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash, generate_password_hash

from app.database import get_db
from app.models import LoginAttempt, User
from app.otp import (
    generate_otp_secret,
    get_otp_qr_data_url,
    get_otp_uri,
    matching_otp_counter,
)


router = APIRouter(prefix="/auth", tags=["Authentication"])

# Configure JWT_SECRET_KEY before starting the application.
SECRET_KEY = os.environ["JWT_SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ENROLLMENT_TOKEN_EXPIRE_MINUTES = 10
PENDING_OTP_EXPIRE_SECONDS = 600
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Used to perform a password check even for unknown usernames.
DUMMY_PASSWORD_HASH = generate_password_hash(
    "dummy-password-for-timing-check",
    method="scrypt",
)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100, pattern=r"^\S+$")
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    two_factor_enabled: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    two_factor_enrollment_required: bool = Field(
        default=False,
        serialization_alias="2fa_enrollment_required",
    )


class TwoFactorConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class TwoFactorSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code_data_url: str


class TwoFactorStatusResponse(BaseModel):
    two_factor_enabled: bool
    access_token: str


def create_access_token(user_id: int, scope: str) -> str:
    now = datetime.now(timezone.utc)
    lifetime = (
        ENROLLMENT_TOKEN_EXPIRE_MINUTES
        if scope == "enroll"
        else ACCESS_TOKEN_EXPIRE_MINUTES
    )

    return jwt.encode(
        {
            "sub": str(user_id),
            "scope": scope,
            "mfa": scope == "full",
            "iat": now,
            "exp": now + timedelta(minutes=lifetime),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def _decode_token_user(token: str, db: Session) -> tuple[dict, User]:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalide ou expiré",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "exp"]},
        )
        user_id = int(payload["sub"])
    except (InvalidTokenError, ValueError, TypeError):
        raise credentials_error from None

    user = db.get(User, user_id)
    if user is None:
        raise credentials_error
    return payload, user


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    payload, user = _decode_token_user(token, db)
    if payload.get("scope") != "full" or payload.get("mfa") is not True:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification MFA requise",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_enrollment_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    payload, user = _decode_token_user(token, db)
    if payload.get("scope") not in {"enroll", "full"}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def _login_bucket_key(username: str, client_host: str) -> str:
    identity = f"{username.casefold()}\0{client_host}".encode()
    return hmac.new(SECRET_KEY.encode(), identity, hashlib.sha256).hexdigest()


def _record_login_attempt(db: Session, bucket_key: str) -> int:
    now = int(time.time())
    cutoff = now - LOGIN_WINDOW_SECONDS
    db.execute(
        LoginAttempt.__table__.delete().where(
            LoginAttempt.window_started < now - (2 * LOGIN_WINDOW_SECONDS)
        )
    )
    statement = sqlite_insert(LoginAttempt).values(
        key=bucket_key,
        window_started=now,
        attempts=1,
    )
    statement = statement.on_conflict_do_update(
        index_elements=[LoginAttempt.key],
        set_={
            "window_started": (
                statement.excluded.window_started
            ),
            "attempts": 1,
        },
        where=LoginAttempt.window_started <= cutoff,
    )
    # A second upsert handles an unexpired bucket without a read/modify/write race.
    result = db.execute(statement.returning(LoginAttempt.attempts))
    attempts = result.scalar_one_or_none()
    if attempts is None:
        result = db.execute(
            sqlite_insert(LoginAttempt)
            .values(key=bucket_key, window_started=now, attempts=1)
            .on_conflict_do_update(
                index_elements=[LoginAttempt.key],
                set_={"attempts": LoginAttempt.attempts + 1},
            )
            .returning(LoginAttempt.attempts)
        )
        attempts = result.scalar_one()
    db.commit()
    return attempts


def _reset_login_attempts(db: Session, bucket_key: str) -> None:
    db.execute(
        update(LoginAttempt)
        .where(LoginAttempt.key == bucket_key)
        .values(attempts=0)
    )
    db.commit()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    data: RegisterRequest,
    db: Session = Depends(get_db),
):
    existing_user = db.scalar(
        select(User).where(User.username == data.username)
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Nom d'utilisateur déjà utilisé",
        )

    user = User(username=data.username)
    user.set_password(data.password)

    db.add(user)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Nom d'utilisateur déjà utilisé",
        ) from None

    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    otp_code: str = Form(default=""),
    db: Session = Depends(get_db),
):
    if len(form.username) > 100 or len(form.password) > 128:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
            headers={"WWW-Authenticate": "Bearer"},
        )

    client_host = request.client.host if request.client else "unknown"
    bucket_key = _login_bucket_key(form.username, client_host)
    attempts = _record_login_attempt(db, bucket_key)
    if attempts > LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de tentatives. Réessayez dans quelques minutes.",
            headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)},
        )

    user = db.scalar(
        select(User).where(User.username == form.username)
    )

    password_hash = (
        user.password_hash if user is not None else DUMMY_PASSWORD_HASH
    )
    valid_password = check_password_hash(password_hash, form.password)

    if user is None or not valid_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scope = "enroll"
    if user.two_factor_enabled:
        counter = matching_otp_counter(user.otp_secret, otp_code)
        if counter is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Code OTP absent ou invalide",
                headers={"WWW-Authenticate": "Bearer"},
            )

        consumed = db.execute(
            update(User)
            .where(
                User.id == user.id,
                (User.last_otp_counter.is_(None))
                | (User.last_otp_counter < counter),
            )
            .values(last_otp_counter=counter)
        )
        if consumed.rowcount != 1:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Code OTP déjà utilisé",
                headers={"WWW-Authenticate": "Bearer"},
            )
        db.commit()
        scope = "full"

    _reset_login_attempts(db, bucket_key)
    return TokenResponse(
        access_token=create_access_token(user.id, scope),
        two_factor_enrollment_required=scope == "enroll",
    )


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
def setup_two_factor(
    response: Response,
    current_user: User = Depends(get_enrollment_user),
    db: Session = Depends(get_db),
):
    if current_user.two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="La 2FA est déjà activée",
        )

    now = int(time.time())
    if (
        current_user.pending_otp_secret is None
        or current_user.pending_otp_expires_at is None
        or current_user.pending_otp_expires_at <= now
    ):
        current_user.pending_otp_secret = generate_otp_secret()
        current_user.pending_otp_expires_at = now + PENDING_OTP_EXPIRE_SECONDS
        db.commit()
        db.refresh(current_user)

    response.headers["Cache-Control"] = "no-store"

    provisioning_uri = get_otp_uri(
        current_user.username,
        current_user.pending_otp_secret,
    )
    return TwoFactorSetupResponse(
        secret=current_user.pending_otp_secret,
        provisioning_uri=provisioning_uri,
        qr_code_data_url=get_otp_qr_data_url(provisioning_uri),
    )


@router.post("/2fa/confirm", response_model=TwoFactorStatusResponse)
def confirm_two_factor(
    data: TwoFactorConfirmRequest,
    request: Request,
    current_user: User = Depends(get_enrollment_user),
    db: Session = Depends(get_db),
):
    client_host = request.client.host if request.client else "unknown"
    bucket_key = _login_bucket_key(f"confirm:{current_user.id}", client_host)
    attempts = _record_login_attempt(db, bucket_key)
    if attempts >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de codes invalides. Réessayez dans cinq minutes.",
            headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)},
        )

    secret = current_user.pending_otp_secret
    if (
        current_user.two_factor_enabled
        or secret is None
        or current_user.pending_otp_expires_at is None
        or current_user.pending_otp_expires_at <= int(time.time())
    ):
        current_user.pending_otp_secret = None
        current_user.pending_otp_expires_at = None
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="La configuration 2FA est absente ou expirée",
        )

    counter = matching_otp_counter(secret, data.code)
    if counter is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code OTP invalide",
        )

    activated = db.execute(
        update(User)
        .where(User.id == current_user.id, User.otp_secret.is_(None))
        .where(User.pending_otp_secret == secret)
        .where(
            (User.last_otp_counter.is_(None))
            | (User.last_otp_counter < counter)
        )
        .values(
            otp_secret=secret,
            pending_otp_secret=None,
            pending_otp_expires_at=None,
            last_otp_counter=counter,
        )
    )
    if activated.rowcount != 1:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Le code OTP a déjà été utilisé ou la configuration a changé",
        )
    db.commit()
    _reset_login_attempts(db, bucket_key)
    return TwoFactorStatusResponse(
        two_factor_enabled=True,
        access_token=create_access_token(current_user.id, "full"),
    )