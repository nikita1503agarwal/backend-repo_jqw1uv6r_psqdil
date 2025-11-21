import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from email_validator import validate_email, EmailNotValidError
from passlib.hash import bcrypt

from database import db, create_document, get_documents
from schemas import User, Profile, Announcement, Session as SessionSchema

app = FastAPI(title="opps.cc API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------- Helpers -----------------------

def now_utc():
    return datetime.now(timezone.utc)


def sanitize_text(text: str) -> str:
    return text.strip()


def validate_url(url: str) -> bool:
    pattern = re.compile(r"^(https?:)//[\w.-]+(?:\:[0-9]+)?(?:/[^\s]*)?$")
    return bool(pattern.match(url))


def hash_password(password: str) -> str:
    return bcrypt.hash(password)


def verify_password(password: str, pw_hash: str) -> bool:
    return bcrypt.verify(password, pw_hash)


def generate_token() -> str:
    return secrets.token_urlsafe(32)


# Simple in-memory rate limiter (per-IP per endpoint)
RATE_LIMIT = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 30


def rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    key = f"{ip}:{request.url.path}"
    window_start = int(now_utc().timestamp() // RATE_LIMIT_WINDOW)
    bucket_key = f"{key}:{window_start}"
    count = RATE_LIMIT.get(bucket_key, 0)
    if count >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Too many requests. Please slow down.")
    RATE_LIMIT[bucket_key] = count + 1


# ----------------------- Models -----------------------

class RegisterInput(BaseModel):
    email: str
    username: str
    password: str = Field(min_length=8)


class LoginInput(BaseModel):
    email_or_username: str
    password: str


class ForgotInput(BaseModel):
    email: str


class ResetInput(BaseModel):
    token: str
    new_password: str = Field(min_length=8)


class LinkInput(BaseModel):
    id: Optional[str] = None
    title: str
    url: str
    style: Optional[str] = "glass"
    order: int = 0


class ProfileInput(BaseModel):
    display_name: str
    bio: Optional[str] = ""
    photo_url: Optional[str] = None
    background: str = "charcoal"
    button_style: str = "glass"
    bio_align: str = "center"
    bio_size: str = "md"
    letter_spacing: str = "normal"
    links: List[LinkInput] = []


# ----------------------- Auth Utilities -----------------------

def get_user_by_email(email: str) -> Optional[dict]:
    return db["user"].find_one({"email": email.lower()})


def get_user_by_username(username: str) -> Optional[dict]:
    return db["user"].find_one({"username": username.lower()})


def get_user_by_id(user_id: str) -> Optional[dict]:
    from bson import ObjectId
    try:
        return db["user"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


def create_session(user_id: str, user_agent: str = None, ip: str = None) -> str:
    token = generate_token()
    session = {
        "user_id": user_id,
        "token": token,
        "user_agent": user_agent,
        "ip": ip,
        "created_at": now_utc(),
        "expires_at": now_utc() + timedelta(days=30),
    }
    db["session"].insert_one(session)
    return token


def get_session(token: str) -> Optional[dict]:
    if not token:
        return None
    session = db["session"].find_one({"token": token})
    if not session:
        return None
    if session.get("expires_at") and session["expires_at"] < now_utc():
        return None
    return session


async def auth_dependency(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ", 1)[1]
    session = get_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    user = get_user_by_id(str(session["user_id"])) if isinstance(session["user_id"], str) else get_user_by_id(session["user_id"])
    if not user or not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="Inactive user")
    return {"user": user, "session": session}


# ----------------------- Public -----------------------

@app.get("/")
def read_root():
    return {"name": "opps.cc", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


# ----------------------- Auth -----------------------

@app.post("/auth/register")
async def register(payload: RegisterInput, request: Request):
    rate_limit(request)
    # verify signups toggle
    cfg = db["config"].find_one({"key": "signups"}) or {"enabled": True}
    if not cfg.get("enabled", True):
        raise HTTPException(status_code=403, detail="Signups are currently disabled")

    try:
        email_info = validate_email(payload.email)
        email = email_info.email
    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail=str(e))

    username = payload.username.lower().strip()
    if not re.match(r"^[a-z0-9_]{3,24}$", username):
        raise HTTPException(status_code=400, detail="Invalid username")

    if get_user_by_email(email) or get_user_by_username(username):
        raise HTTPException(status_code=400, detail="User already exists")

    pw_hash = hash_password(payload.password)

    user_doc = {
        "email": email.lower(),
        "username": username,
        "password_hash": pw_hash,
        "is_admin": False,
        "is_active": True,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    res = db["user"].insert_one(user_doc)
    user_id = str(res.inserted_id)

    # default profile
    profile = {
        "user_id": user_id,
        "username": username,
        "display_name": username,
        "bio": "",
        "photo_url": None,
        "background": "charcoal",
        "button_style": "glass",
        "bio_align": "center",
        "bio_size": "md",
        "letter_spacing": "normal",
        "links": [],
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    db["profile"].insert_one(profile)

    token = create_session(user_id, request.headers.get("user-agent"), request.client.host if request.client else None)

    return {"token": token, "user": {"email": email, "username": username}}


@app.post("/auth/login")
async def login(payload: LoginInput, request: Request):
    rate_limit(request)
    ident = payload.email_or_username.strip().lower()
    user = get_user_by_email(ident) or get_user_by_username(ident)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_session(str(user["_id"]), request.headers.get("user-agent"), request.client.host if request.client else None)
    return {"token": token, "user": {"email": user["email"], "username": user["username"]}}


@app.get("/auth/me")
async def me(ctx: dict = Depends(auth_dependency)):
    user = ctx["user"]
    return {"email": user["email"], "username": user["username"], "is_admin": user.get("is_admin", False)}


@app.post("/auth/logout")
async def logout(ctx: dict = Depends(auth_dependency)):
    token = ctx["session"]["token"]
    db["session"].delete_one({"token": token})
    return {"ok": True}


@app.post("/auth/forgot")
async def forgot(payload: ForgotInput, request: Request):
    rate_limit(request)
    try:
        email = validate_email(payload.email).email
    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail=str(e))
    user = get_user_by_email(email)
    if not user:
        # do not reveal
        return {"ok": True}
    token = generate_token()
    db["password_reset"].insert_one({
        "user_id": str(user["_id"]),
        "token": token,
        "created_at": now_utc(),
        "expires_at": now_utc() + timedelta(hours=1)
    })
    # In a real app, email the token link. For demo, return token.
    return {"ok": True, "token": token}


@app.post("/auth/reset")
async def reset(payload: ResetInput):
    doc = db["password_reset"].find_one({"token": payload.token})
    if not doc or doc.get("expires_at") < now_utc():
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    pw_hash = hash_password(payload.new_password)
    from bson import ObjectId
    db["user"].update_one({"_id": ObjectId(doc["user_id"])}, {"$set": {"password_hash": pw_hash, "updated_at": now_utc()}})
    db["password_reset"].delete_one({"_id": doc["_id"]})
    return {"ok": True}


# ----------------------- Profiles -----------------------

@app.get("/profiles/{username}")
async def public_profile(username: str):
    prof = db["profile"].find_one({"username": username.lower()})
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
    # sanitize output
    prof["_id"] = str(prof["_id"])
    return prof


@app.get("/profiles/me")
async def my_profile(ctx: dict = Depends(auth_dependency)):
    prof = db["profile"].find_one({"user_id": str(ctx["user"]["_id"])})
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
    prof["_id"] = str(prof["_id"]) 
    return prof


@app.put("/profiles/me")
async def update_my_profile(payload: ProfileInput, ctx: dict = Depends(auth_dependency)):
    # validate links
    links = []
    seen_ids = set()
    for i, link in enumerate(payload.links):
        title = sanitize_text(link.title)[:60]
        url = link.url.strip()
        if not validate_url(url):
            raise HTTPException(status_code=400, detail=f"Invalid URL: {url}")
        lid = link.id or secrets.token_hex(6)
        if lid in seen_ids:
            lid = lid + secrets.token_hex(2)
        seen_ids.add(lid)
        style = link.style if link.style in ("black", "white", "glass") else "glass"
        links.append({
            "id": lid,
            "title": title,
            "url": url,
            "style": style,
            "order": int(link.order or 0)
        })
    links.sort(key=lambda x: x["order"])

    updates = {
        "display_name": sanitize_text(payload.display_name)[:60],
        "bio": (payload.bio or "")[:200],
        "photo_url": payload.photo_url or None,
        "background": payload.background if payload.background in ("pure-black", "charcoal", "white-glass", "black-glass") else "charcoal",
        "button_style": payload.button_style if payload.button_style in ("black", "white", "glass") else "glass",
        "bio_align": payload.bio_align if payload.bio_align in ("left", "center") else "center",
        "bio_size": payload.bio_size if payload.bio_size in ("sm", "md", "lg") else "md",
        "letter_spacing": payload.letter_spacing if payload.letter_spacing in ("tight", "normal", "wide") else "normal",
        "links": links,
        "updated_at": now_utc(),
    }

    db["profile"].update_one({"user_id": str(ctx["user"]["_id"])}, {"$set": updates})
    prof = db["profile"].find_one({"user_id": str(ctx["user"]["_id"])})
    prof["_id"] = str(prof["_id"]) 
    return prof


# ----------------------- Admin -----------------------

def require_admin(ctx: dict):
    if not ctx["user"].get("is_admin", False):
        raise HTTPException(status_code=403, detail="Forbidden")


@app.get("/admin/stats")
async def admin_stats(ctx: dict = Depends(auth_dependency)):
    require_admin(ctx)
    users = db["user"].count_documents({})
    profiles = db["profile"].count_documents({})
    views = db["analytics"].count_documents({"type": "profile_view"}) if "analytics" in db.list_collection_names() else 0
    return {"users": users, "profiles": profiles, "views": views}


@app.post("/admin/toggle-signups")
async def toggle_signups(payload: dict, ctx: dict = Depends(auth_dependency)):
    require_admin(ctx)
    enabled = bool(payload.get("enabled", True))
    db["config"].update_one({"key": "signups"}, {"$set": {"key": "signups", "enabled": enabled, "updated_at": now_utc()}}, upsert=True)
    return {"enabled": enabled}


@app.get("/admin/announcements")
async def list_announcements(ctx: dict = Depends(auth_dependency)):
    require_admin(ctx)
    anns = list(db["announcement"].find().sort("created_at", -1))
    for a in anns:
        a["_id"] = str(a["_id"]) 
    return anns


@app.post("/admin/announcements")
async def create_announcement(payload: Announcement, ctx: dict = Depends(auth_dependency)):
    require_admin(ctx)
    doc = payload.model_dump()
    doc["created_at"] = now_utc()
    doc["updated_at"] = now_utc()
    res = db["announcement"].insert_one(doc)
    return {"id": str(res.inserted_id)}


# Simple profile view tracking
@app.post("/analytics/view/{username}")
async def track_view(username: str, request: Request):
    db["analytics"].insert_one({
        "type": "profile_view",
        "username": username.lower(),
        "ip": request.client.host if request.client else None,
        "ua": request.headers.get("user-agent"),
        "at": now_utc(),
    })
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
