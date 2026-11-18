import base64
from io import BytesIO
import time

import pyotp
import qrcode


def generate_otp_secret() -> str:
    return pyotp.random_base32()


def get_otp_uri(username: str, secret: str) -> str:
    """Lien à ajouter dans une application Authenticator."""
    return pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="FastAPI Auth",
    )


def get_otp_qr_data_url(provisioning_uri: str) -> str:
    image = qrcode.make(provisioning_uri)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    encoded_image = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded_image}"


def verify_otp(secret: str, code: str) -> bool:
    """Vérifie le code à 6 chiffres."""
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return False

    return pyotp.TOTP(secret).verify(code, valid_window=0)


def matching_otp_counter(secret: str, code: str) -> int | None:
    """Retourne le pas TOTP courant si le code est valide."""
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None

    totp = pyotp.TOTP(secret)
    counter = int(time.time()) // totp.interval
    if totp.verify(code, for_time=counter * totp.interval, valid_window=0):
        return counter
    return None