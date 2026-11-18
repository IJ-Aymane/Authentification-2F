from sqlalchemy import BigInteger, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    pending_otp_secret: Mapped[str | None] = mapped_column(String(64))
    pending_otp_expires_at: Mapped[int | None] = mapped_column(BigInteger)
    otp_secret: Mapped[str | None] = mapped_column(String(64))
    last_otp_counter: Mapped[int | None] = mapped_column(BigInteger)

    @property
    def two_factor_enabled(self) -> bool:
        return self.otp_secret is not None

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(
            password,
            method="scrypt",
        )

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class LoginAttempt(Base):
    __tablename__ = "auth_login_attempts"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_started: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)