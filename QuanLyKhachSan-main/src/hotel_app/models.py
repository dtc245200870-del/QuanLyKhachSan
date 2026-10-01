"""Database models shared by Login and the future Register slice."""

from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def normalize_email(value: str | None) -> str:
    """Return the canonical account identifier defined by FR-AUTH-001."""

    return (value or "").strip().casefold()


class User(db.Model):
    """Minimal persistent user required for authentication."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Room(db.Model):
    """Persisted room details displayed by the room management page."""

    __tablename__ = "rooms"

    number = db.Column(db.String(10), primary_key=True)
    floor = db.Column(db.String(30), nullable=False)
    room_type = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(20), nullable=False)
    check_in = db.Column(db.String(5))
    check_out = db.Column(db.String(5))
    image_filename = db.Column(db.String(255))

