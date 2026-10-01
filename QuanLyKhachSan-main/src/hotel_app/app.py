"""Minimal Flask application for SCRUM-21 / PB-01 Login."""

from __future__ import annotations

from io import BytesIO
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError
from PIL import Image, UnidentifiedImageError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.utils import secure_filename

from .extensions import csrf, db
from .models import Room, User, normalize_email


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INSTANCE_PATH = PROJECT_ROOT / "instance"
INVALID_CREDENTIAL_MESSAGE = "Email hoặc mật khẩu không đúng"
REGISTER_SUCCESS_MESSAGE = "Tạo tài khoản thành công. Vui lòng đăng nhập."
DEVELOPMENT_DEMO_EMAIL = "demo@example.test"
DEVELOPMENT_DEMO_PASSWORD = "Demo1@Hotel2026"
TRUE_VALUES = {"1", "true", "yes", "on"}
ROOM_FLOORS = (
    {
        "name": "Tầng 1",
        "rooms": (
            {
                "number": "101", "type": "Phòng tiêu chuẩn",
                "status": "Phòng trống", "state": "empty",
                "check_in": None, "check_out": None,
            },
            {
                "number": "102", "type": "Phòng 2 giường đơn",
                "status": "Đang thuê", "state": "occupied",
                "check_in": "14:00", "check_out": "12:00",
            },
            {
                "number": "103", "type": "Phòng tiêu chuẩn",
                "status": "Phòng trống", "state": "empty",
                "check_in": None, "check_out": None,
            },
            {
                "number": "104", "type": "Phòng VIP",
                "status": "Đang thuê", "state": "occupied",
                "check_in": "15:30", "check_out": "11:30",
            },
        ),
    },
    {
        "name": "Tầng 2",
        "rooms": (
            {
                "number": "201", "type": "Phòng 1 giường đôi",
                "status": "Phòng trống", "state": "empty",
                "check_in": None, "check_out": None,
            },
            {
                "number": "202", "type": "Phòng tiêu chuẩn",
                "status": "Đang thuê", "state": "occupied",
                "check_in": "13:15", "check_out": "12:00",
            },
            {
                "number": "203", "type": "Phòng VIP",
                "status": "Phòng trống", "state": "empty",
                "check_in": None, "check_out": None,
            },
            {
                "number": "204", "type": "Phòng 2 giường đơn",
                "status": "Phòng trống", "state": "empty",
                "check_in": None, "check_out": None,
            },
        ),
    },
    {
        "name": "Tầng 3",
        "rooms": (
            {
                "number": "301", "type": "Phòng tiêu chuẩn",
                "status": "Đang thuê", "state": "occupied",
                "check_in": "14:00", "check_out": "12:00",
            },
            {
                "number": "302", "type": "Phòng VIP",
                "status": "Phòng trống", "state": "empty",
                "check_in": None, "check_out": None,
            },
            {
                "number": "303", "type": "Phòng 1 giường đôi",
                "status": "Phòng trống", "state": "empty",
                "check_in": None, "check_out": None,
            },
            {
                "number": "304", "type": "Phòng tiêu chuẩn",
                "status": "Phòng trống", "state": "empty",
                "check_in": None, "check_out": None,
            },
        ),
    },
)
ROOM_TYPE_CATALOG = (
    {
        "name": "Phòng tiêu chuẩn",
        "price": "500,000 VNĐ",
        "capacity": "2 người",
        "description": "Phòng cơ bản đầy đủ tiện nghi",
    },
    {
        "name": "Phòng VIP",
        "price": "1,200,000 VNĐ",
        "capacity": "4 người",
        "description": "Phòng rộng, view biển, có bồn tắm",
    },
)
ROOM_STATES = {
    "empty": "Phòng trống",
    "occupied": "Đang thuê",
    "cleaning": "Đang dọn",
}
IMAGE_FORMATS = {
    ".jpg": {"JPEG"},
    ".jpeg": {"JPEG"},
    ".png": {"PNG"},
    ".webp": {"WEBP"},
}


def _environment(test_config: dict[str, Any] | None) -> str:
    if test_config and "APP_ENV" in test_config:
        return str(test_config["APP_ENV"])
    return os.environ.get("APP_ENV", "production")


def _secret_key(environment: str, test_config: dict[str, Any] | None) -> str:
    if test_config and test_config.get("SECRET_KEY"):
        return str(test_config["SECRET_KEY"])

    configured_key = os.environ.get("SECRET_KEY")
    if configured_key:
        return configured_key

    if environment in {"development", "testing"}:
        return secrets.token_hex(32)

    raise RuntimeError("SECRET_KEY must be configured outside Development.")


def _environment_flag(name: str, default: bool) -> bool:
    """Read a small boolean environment flag without extra dependencies."""

    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().casefold() in TRUE_VALUES


def _seed_demo_user(app: Flask) -> None:
    if (
        app.config["APP_ENV"] != "development"
        or not app.config["SEED_DEMO_USER"]
    ):
        return

    demo_email = normalize_email(app.config.get("DEMO_USER_EMAIL"))
    demo_password = app.config.get("DEMO_USER_PASSWORD") or ""
    if not demo_email or not demo_password:
        return

    existing_user = db.session.execute(
        db.select(User).where(User.email == demo_email)
    ).scalar_one_or_none()
    if existing_user is not None:
        return

    demo_user = User(email=demo_email)
    demo_user.set_password(demo_password)
    db.session.add(demo_user)
    db.session.commit()


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create the small Login application with optional isolated test config."""

    environment = _environment(test_config)
    INSTANCE_PATH.mkdir(parents=True, exist_ok=True)

    app = Flask(__name__, instance_path=str(INSTANCE_PATH))
    app.config.from_mapping(
        APP_ENV=environment,
        SECRET_KEY=_secret_key(environment, test_config),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", "sqlite:///hotel.db"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_NAME="hotel_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=environment not in {"development", "testing"},
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        ROOM_UPLOAD_FOLDER=str(Path(__file__).resolve().parent / "static" / "uploads" / "rooms"),
        SEED_DEMO_USER=_environment_flag(
            "SEED_DEMO_USER", environment == "development"
        ),
        DEMO_USER_EMAIL=(
            os.environ.get("DEMO_USER_EMAIL") or DEVELOPMENT_DEMO_EMAIL
        ),
        DEMO_USER_PASSWORD=(
            os.environ.get("DEMO_USER_PASSWORD") or DEVELOPMENT_DEMO_PASSWORD
        ),
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    csrf.init_app(app)

    def current_user() -> User | None:
        user_id = session.get("user_id")
        if user_id is None:
            return None

        user = db.session.get(User, user_id)
        if user is None:
            session.clear()
        return user

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user() is not None:
            return redirect(url_for("home"))

        email_input = request.form.get("email", "")
        errors: dict[str, str] = {}
        credential_error: str | None = None

        if request.method == "POST":
            password = request.form.get("password", "")
            canonical_email = normalize_email(email_input)

            if not canonical_email:
                errors["email"] = "Vui lòng nhập Email."
            if not password:
                errors["password"] = "Vui lòng nhập Mật khẩu."

            if not errors:
                user = db.session.execute(
                    db.select(User).where(User.email == canonical_email)
                ).scalar_one_or_none()

                password_is_valid = False
                if user is not None:
                    try:
                        password_is_valid = user.check_password(password)
                    except ValueError:
                        app.logger.error("A User record has an invalid password hash.")

                if password_is_valid:
                    session.clear()
                    session["user_id"] = user.id
                    session.permanent = True
                    return redirect(url_for("home"))

                session.pop("user_id", None)
                credential_error = INVALID_CREDENTIAL_MESSAGE

        return render_template(
            "login.html",
            email=email_input,
            errors=errors,
            credential_error=credential_error,
            service_error=None,
        )

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user() is not None:
            return redirect(url_for("home"))

        email_input = request.form.get("email", "")
        errors: dict[str, str] = {}

        if request.method == "POST":
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            canonical_email = normalize_email(email_input)

            if not canonical_email:
                errors["email"] = "Vui lòng nhập Email."
            if not password:
                errors["password"] = "Vui lòng nhập Mật khẩu."
            elif len(password) < 8:
                errors["password"] = "Mật khẩu phải có ít nhất 8 ký tự."
            if not confirm_password:
                errors["confirm_password"] = "Vui lòng xác nhận Mật khẩu."
            elif password and confirm_password != password:
                errors["confirm_password"] = "Mật khẩu xác nhận không khớp"

            if not errors:
                existing_user = db.session.execute(
                    db.select(User).where(User.email == canonical_email)
                ).scalar_one_or_none()

                if existing_user is not None:
                    errors["email"] = "Email đã được sử dụng"
                else:
                    user = User(email=canonical_email)
                    user.set_password(password)
                    db.session.add(user)
                    try:
                        db.session.commit()
                    except IntegrityError:
                        db.session.rollback()
                        errors["email"] = "Email đã được sử dụng"
                    else:
                        flash(REGISTER_SUCCESS_MESSAGE, "success")
                        return redirect(url_for("login"))

        return render_template(
            "register.html",
            email=email_input,
            errors=errors,
            service_error=None,
        )

    @app.route("/")
    def home():
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        return redirect(url_for("room_management"))

    @app.route("/rooms")
    def room_management():
        user = current_user()
        if user is None:
            return redirect(url_for("login"))

        rooms_by_number = {
            room.number: room for room in db.session.scalars(db.select(Room))
        }
        floors = []
        for floor in ROOM_FLOORS:
            rooms = []
            for initial_room in floor["rooms"]:
                room = rooms_by_number[initial_room["number"]]
                rooms.append(
                    {
                        "number": room.number,
                        "type": room.room_type,
                        "status": ROOM_STATES[room.state],
                        "state": room.state,
                        "check_in": room.check_in,
                        "check_out": room.check_out,
                        "image_filename": room.image_filename,
                    }
                )
            floors.append({"name": floor["name"], "rooms": rooms})

        return render_template("home.html", user=user, floors=floors)

    @app.route("/rooms/<room_number>/edit", methods=["GET", "POST"])
    def edit_room(room_number: str):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))

        room = db.session.get(Room, room_number)
        if room is None:
            abort(404)

        form_data = {
            "room_type": room.room_type,
            "state": room.state,
            "check_in": room.check_in or "",
            "check_out": room.check_out or "",
        }
        errors: dict[str, str] = {}

        if request.method == "POST":
            form_data = {
                "room_type": request.form.get("room_type", "").strip(),
                "state": request.form.get("state", "").strip(),
                "check_in": request.form.get("check_in", "").strip(),
                "check_out": request.form.get("check_out", "").strip(),
            }
            if not form_data["room_type"]:
                errors["room_type"] = "Vui lòng nhập thể loại phòng."
            elif len(form_data["room_type"]) > 100:
                errors["room_type"] = "Thể loại phòng không được vượt quá 100 ký tự."
            if form_data["state"] not in ROOM_STATES:
                errors["state"] = "Vui lòng chọn trạng thái phòng hợp lệ."
            for field in ("check_in", "check_out"):
                if form_data[field]:
                    try:
                        datetime.strptime(form_data[field], "%H:%M")
                    except ValueError:
                        errors[field] = "Vui lòng nhập thời gian hợp lệ."

            uploaded_image = request.files.get("image")
            image_bytes = None
            image_extension = None
            if uploaded_image and uploaded_image.filename:
                safe_name = secure_filename(uploaded_image.filename)
                image_extension = Path(safe_name).suffix.casefold()
                allowed_formats = IMAGE_FORMATS.get(image_extension, set())
                image_bytes = uploaded_image.read()
                try:
                    with Image.open(BytesIO(image_bytes)) as image:
                        image_format = image.format
                        if image.width * image.height > 20_000_000:
                            raise ValueError("Ảnh vượt quá kích thước cho phép.")
                        image.verify()
                except (UnidentifiedImageError, OSError, ValueError):
                    errors["image"] = "Tệp tải lên không phải ảnh hợp lệ."
                else:
                    if image_format not in allowed_formats:
                        errors["image"] = "Chỉ chấp nhận ảnh JPG, PNG hoặc WEBP."

            saved_image_path = None
            upload_folder = Path(app.config["ROOM_UPLOAD_FOLDER"])
            if not errors:
                if image_bytes is not None and image_extension is not None:
                    image_filename = f"{uuid4().hex}{image_extension}"
                    upload_folder.mkdir(parents=True, exist_ok=True)
                    saved_image_path = upload_folder / image_filename
                    try:
                        saved_image_path.write_bytes(image_bytes)
                    except OSError:
                        saved_image_path = None
                        errors["form"] = "Không thể lưu ảnh. Vui lòng thử lại."

                if not errors:
                    previous_image = room.image_filename
                    room.room_type = form_data["room_type"]
                    room.state = form_data["state"]
                    room.check_in = form_data["check_in"] or None
                    room.check_out = form_data["check_out"] or None
                    if image_bytes is not None and saved_image_path is not None:
                        room.image_filename = saved_image_path.name
                    try:
                        db.session.commit()
                    except SQLAlchemyError:
                        db.session.rollback()
                        if saved_image_path is not None:
                            saved_image_path.unlink(missing_ok=True)
                        errors["form"] = "Không thể cập nhật phòng. Vui lòng thử lại."
                    else:
                        if previous_image and room.image_filename != previous_image:
                            (upload_folder / previous_image).unlink(missing_ok=True)
                        flash(
                            f"Cập nhật thông tin phòng {room.number} thành công.",
                            "success",
                        )
                        return redirect(url_for("room_management"))

        return render_template(
            "room_edit.html",
            user=user,
            room=room,
            form_data=form_data,
            errors=errors,
            room_states=ROOM_STATES,
        )

    @app.route("/account")
    def account():
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        return redirect(url_for("room_management"))

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("Đăng xuất thành công.", "success")
        return redirect(url_for("login"))

    @app.route("/room-types")
    def room_types():
        user = current_user()
        if user is None:
            return redirect(url_for("login"))

        return render_template("room_types.html", user=user, room_types=ROOM_TYPE_CATALOG)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(_error: CSRFError):
        session.pop("user_id", None)
        template_name = (
            "register.html" if request.endpoint == "register" else "login.html"
        )
        return (
            render_template(
                template_name,
                email="",
                errors={},
                credential_error=None,
                service_error=(
                    "Phiên biểu mẫu không hợp lệ hoặc đã hết hạn. Vui lòng thử lại."
                ),
            ),
            400,
        )

    @app.errorhandler(SQLAlchemyError)
    def handle_database_error(_error: SQLAlchemyError):
        db.session.rollback()
        session.pop("user_id", None)
        app.logger.error("A database operation failed.")
        template_name = (
            "register.html" if request.endpoint == "register" else "login.html"
        )
        return (
            render_template(
                template_name,
                email="",
                errors={},
                credential_error=None,
                service_error=(
                    "Hệ thống tạm thời không thể xử lý yêu cầu. Vui lòng thử lại."
                ),
            ),
            503,
        )

    with app.app_context():
        db.create_all()
        _seed_demo_user(app)
        for floor in ROOM_FLOORS:
            for initial_room in floor["rooms"]:
                if db.session.get(Room, initial_room["number"]) is None:
                    db.session.add(
                        Room(
                            number=initial_room["number"],
                            floor=floor["name"],
                            room_type=initial_room["type"],
                            state=initial_room["state"],
                            check_in=initial_room["check_in"],
                            check_out=initial_room["check_out"],
                        )
                    )
        db.session.commit()

    return app


app = create_app()