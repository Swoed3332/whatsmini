from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import json
import os
from pathlib import Path

from db import init_db, connect
from auth import hash_password, verify_password, create_token, decode_token


BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")


@app.on_event("startup")
def startup():
    init_db()


# ---------------- MODELS ----------------

class RegisterBody(BaseModel):
    username: str
    password: str


class LoginBody(BaseModel):
    username: str
    password: str


class KeyBody(BaseModel):
    token: str
    public_key_jwk: dict


# ---------------- HELPERS ----------------

def get_user(username: str):
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row


# ---------------- AUTH ----------------

@app.post("/api/register")
def register(body: RegisterBody):
    conn = connect()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users(username,password_hash) VALUES(?,?)",
            (body.username, hash_password(body.password))
        )
        conn.commit()
    except Exception as e:
        print("REGISTER ERROR:", e)
        conn.close()
        raise HTTPException(400, str(e))

    conn.close()
    return {"ok": True}


@app.post("/api/login")
def login(body: LoginBody):
    row = get_user(body.username)

    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "invalid credentials")

    token = create_token(body.username)
    return {"token": token, "username": body.username}


# ---------------- KEYS ----------------

@app.post("/api/keys")
def set_key(body: KeyBody):
    username = decode_token(body.token)
    if not username:
        raise HTTPException(401, "invalid token")

    user = get_user(username)

    conn = connect()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO user_keys(user_id, public_key_jwk, updated_at)
        VALUES(?,?,datetime('now'))
        ON CONFLICT(user_id) DO UPDATE SET
        public_key_jwk=excluded.public_key_jwk,
        updated_at=datetime('now')
    """, (user["id"], json.dumps(body.public_key_jwk)))

    conn.commit()
    conn.close()

    return {"ok": True}


@app.get("/api/keys/{username}")
def get_key(username: str):
    user = get_user(username)
    if not user:
        raise HTTPException(404, "user not found")

    conn = connect()
    cur = conn.cursor()

    cur.execute("SELECT public_key_jwk FROM user_keys WHERE user_id=?", (user["id"],))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(404, "key not found")

    return {"public_key_jwk": json.loads(row["public_key_jwk"])}


# ---------------- UPLOAD ----------------

@app.post("/api/upload")
async def upload(token: str = Form(...), file: UploadFile = File(...)):
    username = decode_token(token)
    if not username:
        raise HTTPException(401, "invalid token")

    name = "".join(c for c in file.filename if c.isalnum() or c in "._-")
    out = f"{username}_{os.urandom(4).hex()}_{name}"

    path = UPLOAD_DIR / out
    content = await file.read()
    path.write_bytes(content)

    return {"url": f"/uploads/{out}"}


# ---------------- WEBSOCKET ----------------

class Manager:
    def __init__(self):
        self.clients = {}

    async def connect(self, username, ws):
        await ws.accept()
        self.clients[username] = ws

    def disconnect(self, username):
        self.clients.pop(username, None)

    async def send(self, to_user, data):
        ws = self.clients.get(to_user)
        if ws:
            await ws.send_text(json.dumps(data))


manager = Manager()


@app.websocket("/ws")
async def ws(ws: WebSocket):
    token = ws.query_params.get("token")
    username = decode_token(token)

    if not username:
        await ws.close()
        return

    await manager.connect(username, ws)

    try:
        while True:
            data = json.loads(await ws.receive_text())
            to = data.get("to")

            if to:
                data["from"] = username
                await manager.send(to, data)

    except WebSocketDisconnect:
        manager.disconnect(username)
