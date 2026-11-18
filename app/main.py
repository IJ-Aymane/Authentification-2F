from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from app.auth import router as auth_router
from app.database import Base, engine
from app.models import LoginAttempt, User


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(auth_router)

INDEX_FILE = Path(__file__).resolve().parent / "static" / "index.html"


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(INDEX_FILE)