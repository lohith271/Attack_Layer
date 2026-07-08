from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os
from app.database.session import engine
from app.database.session import Base
import app.database.models
from app.api.memory import router as memory_router
from app.api.classifier import (
    router as classifier_router
)
from app.api.threat import (
    router as threat_router
)
from app.api.sensitive import (
    router as sensitive_router
)
from app.api.request_analyzer import (
    router as request_router
)
from app.api.security import (
    router as security_router
)
from app.api.audit import (
    router as audit_router
)
from app.api.chat import (
    router as chat_router
)
from app.api.export import (
    router as export_router
)
from app.api.tool_policy import (
    router as tool_policy_router
)
from app.api.propagation import (
    router as propagation_router
)
from app.api.research import (
    router as research_router
)
from app.api.evaluation import (
    router as evaluation_router
)
from app.api.hitl import (
    router as hitl_router
)
from app.database.migrate import run_migrations
from app.api.admin import router as admin_router
from app.data.dataset_loader import bootstrap_prototypes

app = FastAPI(
    title="AttackLayer",
    description="AI Memory Security Platform — NeuroSymbolic Memory Protection",
    version="3.0.0"
)
Base.metadata.create_all(bind=engine)
run_migrations()
bootstrap_prototypes()
app.include_router(memory_router)
app.include_router(classifier_router)
app.include_router(
    threat_router
)
app.include_router(
    sensitive_router
)
app.include_router(
    request_router
)
app.include_router(
    security_router
)
app.include_router(
    audit_router
)
app.include_router(
    chat_router
)
app.include_router(
    export_router
)
app.include_router(
    tool_policy_router
)
app.include_router(
    propagation_router
)
app.include_router(
    research_router
)
app.include_router(
    evaluation_router
)
app.include_router(admin_router)
app.include_router(hitl_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

figures_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "figures")
if os.path.exists(figures_path):
    app.mount("/static/figures", StaticFiles(directory=figures_path), name="figures")


@app.get("/")
async def root():
    return {
        "project": "AttackLayer",
        "status": "running",
        "version": "3.0.0"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }