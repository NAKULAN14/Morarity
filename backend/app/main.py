from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router

app = FastAPI(
    title="Moriarty — Agentic AI Structural Security Patch Verification",
    description="Adaptive security patch verification API for SQL injection and security invariants.",
    version="0.1.0",
)

# Enable CORS for local workstation frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.get("/")
def root():
    return {
        "project": "Moriarty",
        "description": "Agentic AI Structural Security Patch Verification",
        "status": "online",
        "api_docs": "/docs",
    }
