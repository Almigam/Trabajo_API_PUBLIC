from fastapi import FastAPI
from app.routers.users import users
from app.routers.auth import auth
from app.routers.messages import messages
from app.routers.assets import assets

app = FastAPI(title="Secure API Starter")

@app.get("/health")
def health():
    return {"status": "ok"}

app.include_router(auth.router, prefix="/auth", tags=["Authetication"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])
app.include_router(assets.router, prefix="/assets", tags=["Assets"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
