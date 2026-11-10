from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Request, UploadFile, File, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
from collections import deque
import sqlite3, hashlib, secrets, os, json, uuid, re, importlib, traceback

MAX_TEXT, MAX_HISTORY = 2000, 200
BASE = os.path.dirname(__file__)
DB = os.path.join(BASE, "chat.db")
UPLOAD_DIR  = os.path.join(BASE, "static", "uploads")
AVATAR_DIR  = os.path.join(BASE, "static", "avatars")
STICKER_DIR = os.path.join(BASE, "static", "stickers")
FILE_DIR    = os.path.join(BASE, "static", "files")

for d in (UPLOAD_DIR, AVATAR_DIR, STICKER_DIR, FILE_DIR):
    os.makedirs(d, exist_ok=True)

IMG_TYPES = {"image/png":"png","image/jpeg":"jpg","image/gif":"gif","image/webp":"webp"}


def _ws_engine():
    for mod in ("websockets", "wsproto"):
        try:
            importlib.import_module(mod)
            return mod
        except ImportError:
            pass
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    e = _ws_engine()
    print(f"{'✅' if e else '⚠️'} WebSocket 引擎: {e or '缺失 → pip install uvicorn[standard]'}")
    init_db()
    yield


app = FastAPI(title="NEXUS Chat", lifespan=lifespan)


@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail if isinstance(exc.detail, str) else str(exc.detail)})


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    traceback.print_exc()
    return JSONResponse(status_code=500, content={"detail": f"服务器内部错误：{type(exc).__name__}: {exc}"})


def db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        avatar TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        created_at TEXT NOT NULL)""")
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "avatar" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''")
    if "bio" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''")
    
    conn.execute("""CREATE TABLE IF NOT EXISTS stickers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        name TEXT DEFAULT '',
        created_at TEXT NOT NULL)""")
    conn.commit()
    conn.close()


def hash_pw(password: str, salt: str | None = None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
    return h.hex(), salt


sessions: dict[str, dict] = {}


def get_session(authorization: str | None) -> dict:
    token = (authorization or "").replace("Bearer ", "")
    s = sessions.get(token)
    if not s:
        raise HTTPException(401, "未登录")
    return s


def save_upload(file: UploadFile, folder: str, prefix: str, max_bytes: int) -> str:
    if file.content_type not in IMG_TYPES:
        raise HTTPException(400, "仅支持 png / jpg / gif / webp")
    data = file.file.read()
    if len(data) > max_bytes:
        raise HTTPException(400, f"图片不能超过 {max_bytes // (1024*1024)}MB")
    name = f"{prefix}_{uuid.uuid4().hex[:10]}.{IMG_TYPES[file.content_type]}"
    with open(os.path.join(folder, name), "wb") as f:
        f.write(data)
    return name


# ---------------- API Routes ----------------

class AuthReq(BaseModel):
    username: str
    password: str


class ProfileReq(BaseModel):
    bio: str = ""


class PasswordReq(BaseModel):
    old_password: str
    new_password: str


@app.post("/api/register")
async def register(req: AuthReq):
    u = req.username.strip()
    if not (2 <= len(u) <= 16):
        raise HTTPException(400, "用户名 2-16 字符")
    if not re.fullmatch(r"[\w\u4e00-\u9fa5]+", u):
        raise HTTPException(400, "用户名仅支持字母、数字、下划线、中文")
    if len(req.password) < 4:
        raise HTTPException(400, "密码至少 4 位")
    ph, salt = hash_pw(req.password)
    conn = db()
    try:
        cur = conn.execute(
            "INSERT INTO users(username,password_hash,salt,created_at) VALUES(?,?,?,?)",
            (u, ph, salt, datetime.now().isoformat()))
        conn.commit()
        uid = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(400, "用户名已存在")
    conn.close()
    token = secrets.token_urlsafe(24)
    sessions[token] = {"id": uid, "username": u}
    return {"token": token, "id": uid, "name": u, "avatar": "", "bio": ""}


@app.post("/api/login")
async def login(req: AuthReq):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (req.username.strip(),)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(400, "用户名或密码错误")
    ph, _ = hash_pw(req.password, row["salt"])
    if ph != row["password_hash"]:
        raise HTTPException(400, "用户名或密码错误")
    token = secrets.token_urlsafe(24)
    sessions[token] = {"id": row["id"], "username": row["username"]}
    return {"token": token, "id": row["id"], "name": row["username"],
            "avatar": row["avatar"] or "", "bio": row["bio"] or ""}


@app.get("/api/me")
async def me(authorization: str = Header(None)):
    s = get_session(authorization)
    conn = db()
    row = conn.execute("SELECT id, username, avatar, bio FROM users WHERE id=?", (s["id"],)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "用户不存在")
    return {"id": row["id"], "name": row["username"],
            "avatar": row["avatar"] or "", "bio": row["bio"] or ""}


@app.post("/api/profile")
async def update_profile(req: ProfileReq, authorization: str = Header(None)):
    s = get_session(authorization)
    conn = db()
    conn.execute("UPDATE users SET bio=? WHERE id=?", (req.bio.strip()[:100], s["id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/password")
async def change_password(req: PasswordReq, authorization: str = Header(None)):
    s = get_session(authorization)
    if len(req.new_password) < 4:
        raise HTTPException(400, "新密码至少 4 位")
    conn = db()
    row = conn.execute("SELECT salt, password_hash FROM users WHERE id=?", (s["id"],)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(401, "用户不存在")
    ph, _ = hash_pw(req.old_password, row["salt"])
    if ph != row["password_hash"]:
        conn.close()
        raise HTTPException(400, "旧密码错误")
    new_ph, new_salt = hash_pw(req.new_password)
    conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?",
                 (new_ph, new_salt, s["id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/avatar")
async def upload_avatar(file: UploadFile = File(...), authorization: str = Header(None)):
    s = get_session(authorization)
    name = save_upload(file, AVATAR_DIR, f"u{s['id']}", 2 * 1024 * 1024)
    url = f"/static/avatars/{name}"
    conn = db()
    conn.execute("UPDATE users SET avatar=? WHERE id=?", (url, s["id"]))
    conn.commit()
    conn.close()
    return {"url": url}


@app.post("/api/upload")
async def upload(file: UploadFile = File(...), authorization: str = Header(None)):
    get_session(authorization)
    name = save_upload(file, UPLOAD_DIR, "img", 5 * 1024 * 1024)
    return {"url": f"/static/uploads/{name}"}


@app.post("/api/upload_file")
async def upload_file(file: UploadFile = File(...), authorization: str = Header(None)):
    get_session(authorization)
    data = file.file.read()
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(400, "文件不能超过 20MB")
    ext = os.path.splitext(file.filename)[1] if file.filename else ""
    fname = f"f_{uuid.uuid4().hex[:10]}{ext}"
    with open(os.path.join(FILE_DIR, fname), "wb") as f:
        f.write(data)
    return {
        "url": f"/static/files/{fname}",
        "name": file.filename,
        "size": len(data)
    }


@app.post("/api/stickers")
async def add_sticker(file: UploadFile = File(...), name: str = Query(""),
                      authorization: str = Header(None)):
    s = get_session(authorization)
    fname = save_upload(file, STICKER_DIR, f"s{s['id']}", 1024 * 1024)
    url = f"/static/stickers/{fname}"
    conn = db()
    cur = conn.execute(
        "INSERT INTO stickers(user_id,url,name,created_at) VALUES(?,?,?,?)",
        (s["id"], url, name[:20], datetime.now().isoformat()))
    conn.commit()
    sid = cur.lastrowid
    conn.close()
    return {"id": sid, "url": url, "name": name[:20]}


@app.get("/api/stickers")
async def list_stickers(authorization: str = Header(None)):
    s = get_session(authorization)
    conn = db()
    rows = conn.execute(
        "SELECT id, url, name FROM stickers WHERE user_id=? ORDER BY id DESC",
        (s["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.delete("/api/stickers/{sid}")
async def del_sticker(sid: int, authorization: str = Header(None)):
    s = get_session(authorization)
    conn = db()
    row = conn.execute("SELECT url FROM stickers WHERE id=? AND user_id=?",
                       (sid, s["id"])).fetchone()
    if row:
        conn.execute("DELETE FROM stickers WHERE id=?", (sid,))
        conn.commit()
        path = os.path.join(BASE, row["url"].lstrip("/"))
        try: os.remove(path)
        except OSError: pass
    conn.close()
    return {"ok": True}


# ---------------- WebSocket ----------------

class Online:
    def __init__(self):
        self.conns: dict[WebSocket, dict] = {}

    def users(self):
        seen = {}
        for d in self.conns.values():
            seen[d["id"]] = {"id": d["id"], "name": d["username"], "avatar": d.get("avatar", "")}
        return list(seen.values())


online = Online()
public_history: deque = deque(maxlen=MAX_HISTORY)
dm_history: dict[tuple, deque] = {}


async def broadcast(payload: dict, exclude: WebSocket | None = None):
    text = json.dumps(payload, ensure_ascii=False)
    dead = []
    for ws in list(online.conns):
        if ws is exclude:
            continue
        try:
            await ws.send_text(text)
        except Exception:
            dead.append(ws)
    for ws in dead:
        online.conns.pop(ws, None)


async def broadcast_users():
    await broadcast({"type": "users", "users": online.users()})


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket, token: str = Query("")):
    await ws.accept()
    sess = sessions.get(token)
    if not sess:
        try:
            await ws.send_text(json.dumps({"type": "error", "code": "auth", "message": "登录已失效，请重新登录"}))
            await ws.close(4002)
        except Exception:
            pass
        return

    conn = db()
    row = conn.execute("SELECT avatar, bio FROM users WHERE id=?", (sess["id"],)).fetchone()
    conn.close()
    avatar = (row["avatar"] if row else "") or ""
    bio = (row["bio"] if row else "") or ""
    uid, uname = sess["id"], sess["username"]

    online.conns[ws] = {"id": uid, "username": uname, "avatar": avatar, "bio": bio}

    await ws.send_text(json.dumps({
        "type": "init",
        "me": {"id": uid, "name": uname, "avatar": avatar, "bio": bio},
        "users": online.users(),
        "history": list(public_history),
    }, ensure_ascii=False))
    await broadcast({"type": "system", "text": f"{uname} 上线了"}, exclude=ws)
    await broadcast_users()

    try:
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except Exception:
                continue
            t = data.get("type")

            if t == "msg":
                text = str(data.get("text", "")).strip()[:MAX_TEXT]
                image = data.get("image") or None
                file_data = data.get("file") or None
                
                if image and not (str(image).startswith("/static/uploads/") or str(image).startswith("/static/stickers/")):
                    image = None
                if file_data and not str(file_data.get("url","")).startswith("/static/files/"):
                    file_data = None
                    
                if not text and not image and not file_data:
                    continue
                to_id = data.get("to")
                now = datetime.now().strftime("%H:%M:%S")

                mentions = []
                if text:
                    for name in set(re.findall(r"@([\w\u4e00-\u9fa5]{1,16})", text)):
                        if any(u["name"] == name for u in online.users()) and name != uname:
                            mentions.append(name)

                msg = {
                    "type": "msg",
                    "id": uuid.uuid4().hex[:12],
                    "from": {"id": uid, "name": uname, "avatar": avatar},
                    "text": text,
                    "image": image,
                    "file": file_data,
                    "to": to_id,
                    "time": now,
                    "mentions": mentions,
                }

                if to_id:
                    key = tuple(sorted([uid, int(to_id)]))
                    dm_history.setdefault(key, deque(maxlen=100)).append(msg)
                    for cws, cd in list(online.conns.items()):
                        if cd["id"] in (uid, int(to_id)):
                            try:
                                await cws.send_text(json.dumps(msg, ensure_ascii=False))
                            except Exception:
                                pass
                else:
                    public_history.append(msg)
                    await broadcast(msg)
                    for name in mentions:
                        for cws, cd in list(online.conns.items()):
                            if cd["username"] == name:
                                try:
                                    await cws.send_text(json.dumps({
                                        "type": "mention", "by": uname,
                                        "text": (text or "[附件]")[:80],
                                    }, ensure_ascii=False))
                                except Exception:
                                    pass

            elif t == "typing":
                to_id = data.get("to")
                payload = {"type": "typing", "id": uid, "name": uname, "to": to_id}
                for cws, cd in list(online.conns.items()):
                    if cws is ws:
                        continue
                    if to_id is None or cd["id"] in (uid, int(to_id)):
                        try:
                            await cws.send_text(json.dumps(payload, ensure_ascii=False))
                        except Exception:
                            pass

            elif t == "dm_history":
                with_id = int(data.get("with", 0))
                key = tuple(sorted([uid, with_id]))
                hist = list(dm_history.get(key, []))
                await ws.send_text(json.dumps(
                    {"type": "dm_history", "with": with_id, "history": hist},
                    ensure_ascii=False))

            elif t == "refresh":
                conn = db()
                row = conn.execute("SELECT avatar, bio FROM users WHERE id=?", (uid,)).fetchone()
                conn.close()
                if row:
                    new_avatar = row["avatar"] or ""
                    online.conns[ws]["avatar"] = new_avatar
                    online.conns[ws]["bio"] = row["bio"] or ""
                    avatar = new_avatar
                await broadcast_users()

            elif t == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))

    except WebSocketDisconnect:
        pass
    except Exception:
        traceback.print_exc()
    finally:
        online.conns.pop(ws, None)
        await broadcast({"type": "system", "text": f"{uname} 下线了"})
        await broadcast_users()


STATIC_DIR = os.path.join(BASE, "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))