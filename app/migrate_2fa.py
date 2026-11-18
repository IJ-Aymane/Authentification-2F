import sqlite3
from datetime import datetime
from pathlib import Path

from sqlalchemy import inspect

from app.database import DB_PATH, engine
from app.models import Base


def migrate() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup_path = DB_PATH.with_name(f"{DB_PATH.name}.backup-{timestamp}")

    with sqlite3.connect(DB_PATH) as source, sqlite3.connect(backup_path) as backup:
        source.backup(backup)

    with engine.begin() as connection:
        columns = {
            column["name"]
            for column in inspect(connection).get_columns("users")
        }
        for name, sql_type in (
            ("pending_otp_secret", "VARCHAR(64)"),
            ("pending_otp_expires_at", "BIGINT"),
            ("otp_secret", "VARCHAR(64)"),
            ("last_otp_counter", "BIGINT"),
        ):
            if name not in columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE users ADD COLUMN {name} {sql_type}"
                )

    Base.metadata.create_all(bind=engine, tables=[Base.metadata.tables["auth_login_attempts"]])
    return backup_path


if __name__ == "__main__":
    print(f"Migration terminée. Sauvegarde : {migrate()}")