from fastapi import FastAPI

app = FastAPI(title="xray-discord-backend")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
