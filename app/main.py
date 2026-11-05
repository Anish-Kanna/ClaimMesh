from fastapi import FastAPI

app = FastAPI(title="ClaimMesh")

@app.get("/health")
def health():
    return {"status": "healthy", "service": "ClaimMesh"}

@app.get("/info")
def info():
    return {"project": "ClaimMesh", "version": "0.1.0", "description": "Software supply-chain evidence composition and verification system"}