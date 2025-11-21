"""
Database Schemas for opps.cc

Each Pydantic model maps to a MongoDB collection whose name is the lowercase class name.

Collections:
- User           -> "user"
- Session        -> "session"
- Profile        -> "profile"
- Announcement   -> "announcement"
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Literal


class User(BaseModel):
    email: str = Field(..., description="User email (unique)")
    username: str = Field(..., min_length=3, max_length=24, pattern=r"^[a-z0-9_]+$", description="Public username (unique, lowercase)")
    password_hash: str = Field(..., description="BCrypt password hash")
    is_admin: bool = Field(False)
    is_active: bool = Field(True)


class Session(BaseModel):
    user_id: str
    token: str
    user_agent: Optional[str] = None
    ip: Optional[str] = None
    expires_at: Optional[str] = None  # ISO string for simplicity


class Link(BaseModel):
    id: str
    title: str = Field(..., max_length=60)
    url: str = Field(..., description="https://...")
    style: Literal["black", "white", "glass"] = "glass"
    order: int = 0


class Profile(BaseModel):
    user_id: str
    username: str
    display_name: str = Field(..., max_length=60)
    bio: Optional[str] = Field("", max_length=200)
    photo_url: Optional[str] = None
    background: Literal["pure-black", "charcoal", "white-glass", "black-glass"] = "charcoal"
    button_style: Literal["black", "white", "glass"] = "glass"
    bio_align: Literal["left", "center"] = "center"
    bio_size: Literal["sm", "md", "lg"] = "md"
    letter_spacing: Literal["tight", "normal", "wide"] = "normal"
    links: List[Link] = []


class Announcement(BaseModel):
    title: str
    body: str
    active: bool = True
