import os

os.environ["JWT_SECRET_KEY"] = "test-signing-key-not-for-production-32-bytes-minimum"

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import LoginAttempt


@pytest.fixture
def test_client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        with TestingSession() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client, TestingSession
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def test_enrollment_then_mfa_login_and_replay_rejection(test_client):
    client, testing_session = test_client
    credentials = {"username": "alice", "password": "correct-horse-battery"}

    registered = client.post("/auth/register", json=credentials)
    assert registered.status_code == 201

    login = client.post("/auth/login", data=credentials)
    assert login.status_code == 200
    login_data = login.json()
    assert login_data["2fa_enrollment_required"] is True
    enrollment_headers = {
        "Authorization": f"Bearer {login_data['access_token']}"
    }

    assert client.get("/auth/me", headers=enrollment_headers).status_code == 401

    setup = client.post("/auth/2fa/setup", headers=enrollment_headers)
    assert setup.status_code == 200
    assert setup.headers["cache-control"] == "no-store"
    setup_data = setup.json()
    assert setup_data["provisioning_uri"].startswith("otpauth://totp/")
    assert setup_data["qr_code_data_url"].startswith("data:image/png;base64,")

    confirm_url = "/auth/2fa/confirm"
    valid_code = pyotp.TOTP(setup_data["secret"]).now()
    wrong_code_value = f"{(int(valid_code) + 1) % 1_000_000:06d}"
    for _ in range(4):
        wrong_code = client.post(
            confirm_url,
            headers=enrollment_headers,
            json={"code": wrong_code_value},
        )
        assert wrong_code.status_code == 400
    locked = client.post(
        confirm_url,
        headers=enrollment_headers,
        json={"code": wrong_code_value},
    )
    assert locked.status_code == 429

    with testing_session() as db:
        db.execute(delete(LoginAttempt))
        db.commit()

    code = valid_code
    confirmed = client.post(
        confirm_url,
        headers=enrollment_headers,
        json={"code": code},
    )
    assert confirmed.status_code == 200
    full_token = confirmed.json()["access_token"]
    full_headers = {"Authorization": f"Bearer {full_token}"}
    assert client.get("/auth/me", headers=full_headers).status_code == 200

    password_only_login = client.post("/auth/login", data=credentials)
    assert password_only_login.status_code == 401

    replay_login = client.post(
        "/auth/login",
        data={**credentials, "otp_code": code},
    )
    assert replay_login.status_code == 401