"""Local-only demo API. Do not deploy publicly without external authentication."""
from __future__ import annotations

def create_app():
    try:from fastapi import FastAPI,HTTPException
    except ImportError as exc:raise RuntimeError("Install pip install -e '.[api]'") from exc
    from agentshield.security.engine import Identity
    from agentshield.tools.sandbox import SyntheticWorkspace
    app=FastAPI(title="AgentShield synthetic demo",version="0.2.0")
    workspace=SyntheticWorkspace()
    @app.get("/health")
    def health():return {"status":"ok","synthetic":True}
    @app.get("/demo/document/{document_id}")
    def document(document_id:str):
        # Fixed demo identity, never infer authentication from request parameters.
        identity=Identity("demo-analyst","acme",frozenset({"search_documents"}))
        result=workspace.execute(identity,"search_documents",{"tenant":"acme","document_id":document_id})
        if not result.allowed:raise HTTPException(status_code=403,detail=result.reason)
        return {"content":result.value,"classification":result.provenance[0].classification}
    return app
