import os
import sqlite3
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr

DB_PATH = os.getenv("DATABASE_PATH", "emergency_sos.db")
TOKEN_LIFETIME_HOURS = int(os.getenv("TOKEN_LIFETIME_HOURS", "72"))

app = FastAPI(
    title="Emergency SOS API",
    description="Backend API for user accounts, emergency contacts, and SOS event history.",
    version="1.0.0",
)

# For production, replace "*" with the exact deployed frontend origin(s).
origins = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if origins == ["*"] else origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sos_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            latitude REAL,
            longitude REAL,
            accuracy_m REAL,
            message TEXT NOT NULL DEFAULT 'Emergency SOS triggered',
            status TEXT NOT NULL DEFAULT 'created',
            created_at TEXT NOT NULL
        );
        """)

init_db()

class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class ContactIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    phone: str = Field(min_length=3, max_length=30)

class ContactUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    phone: Optional[str] = Field(default=None, min_length=3, max_length=30)

class SOSIn(BaseModel):
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    accuracy_m: Optional[float] = Field(default=None, ge=0, le=100000)
    message: str = Field(default="Emergency SOS triggered", min_length=1, max_length=500)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def password_hash(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return salt.hex() + "$" + digest.hex()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expiry = (datetime.now(timezone.utc) + timedelta(hours=TOKEN_LIFETIME_HOURS)).isoformat()
    with connect() as db:
        db.execute(
            "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_id, expiry),
        )
    return token

def current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Please log in to continue.")
    token = authorization[7:].strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with connect() as db:
        row = db.execute("""
            SELECT users.id, users.name, users.email, sessions.expires_at
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
        """, (token_hash,)).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid session. Please log in again.")
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
        return {"id": row["id"], "name": row["name"], "email": row["email"]}

@app.get("/")
def root():
    return {"message": "Emergency SOS API is running", "docs": "/docs"}

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Emergency SOS API"}

@app.post("/api/auth/register", status_code=201)
def register(data: RegisterIn):
    with connect() as db:
        try:
            cur = db.execute(
                "INSERT INTO users(name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (data.name.strip(), data.email.lower(), password_hash(data.password), now_iso()),
            )
            user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="An account with this email already exists.")
    return {"message": "Account created successfully", "user_id": user_id}

@app.post("/api/auth/login")
def login(data: LoginIn):
    with connect() as db:
        user = db.execute(
            "SELECT id, name, email, password_hash FROM users WHERE email = ?",
            (data.email.lower(),),
        ).fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    token = create_session(user["id"])
    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user["id"], "name": user["name"], "email": user["email"]},
    }

@app.post("/api/auth/logout")
def logout(user=Depends(current_user), authorization: str = Header(...)):
    token = authorization[7:].strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    return {"message": "Logged out successfully"}

@app.get("/api/me")
def me(user=Depends(current_user)):
    return user

@app.get("/api/contacts")
def list_contacts(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute(
            "SELECT id, name, phone, created_at FROM contacts WHERE user_id = ? ORDER BY id DESC",
            (user["id"],),
        ).fetchall()
    return [dict(row) for row in rows]

@app.post("/api/contacts", status_code=201)
def add_contact(data: ContactIn, user=Depends(current_user)):
    with connect() as db:
        cur = db.execute(
            "INSERT INTO contacts(user_id, name, phone, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], data.name.strip(), data.phone.strip(), now_iso()),
        )
        row = db.execute(
            "SELECT id, name, phone, created_at FROM contacts WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
    return dict(row)

@app.put("/api/contacts/{contact_id}")
def update_contact(contact_id: int, data: ContactUpdate, user=Depends(current_user)):
    changes = data.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Provide a name or phone number to update.")
    with connect() as db:
        row = db.execute(
            "SELECT id FROM contacts WHERE id = ? AND user_id = ?",
            (contact_id, user["id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Contact not found.")
        for field, value in changes.items():
            db.execute(
                f"UPDATE contacts SET {field} = ? WHERE id = ? AND user_id = ?",
                (value.strip(), contact_id, user["id"]),
            )
        updated = db.execute(
            "SELECT id, name, phone, created_at FROM contacts WHERE id = ?",
            (contact_id,),
        ).fetchone()
    return dict(updated)

@app.delete("/api/contacts/{contact_id}")
def delete_contact(contact_id: int, user=Depends(current_user)):
    with connect() as db:
        cur = db.execute(
            "DELETE FROM contacts WHERE id = ? AND user_id = ?",
            (contact_id, user["id"]),
        )
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Contact not found.")
    return {"message": "Contact deleted successfully"}

@app.post("/api/sos", status_code=201)
def create_sos(data: SOSIn, user=Depends(current_user)):
    if (data.latitude is None) != (data.longitude is None):
        raise HTTPException(status_code=400, detail="Send both latitude and longitude, or neither.")
    with connect() as db:
        cur = db.execute("""
            INSERT INTO sos_alerts(user_id, latitude, longitude, accuracy_m, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user["id"], data.latitude, data.longitude, data.accuracy_m, data.message, now_iso()))
        alert = db.execute(
            "SELECT id, latitude, longitude, accuracy_m, message, status, created_at FROM sos_alerts WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
    # This records the SOS event; it does NOT automatically call emergency services or send SMS.
    return {"message": "SOS event recorded", "alert": dict(alert)}

@app.get("/api/sos/history")
def sos_history(user=Depends(current_user), limit: int = 50):
    limit = max(1, min(limit, 100))
    with connect() as db:
        rows = db.execute("""
            SELECT id, latitude, longitude, accuracy_m, message, status, created_at
            FROM sos_alerts WHERE user_id = ? ORDER BY id DESC LIMIT ?
        """, (user["id"], limit)).fetchall()
    return [dict(row) for row in rows]
