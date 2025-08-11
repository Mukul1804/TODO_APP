import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, Response, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------------------------------------------------------
# App & Config
# -----------------------------------------------------------------------------
app = Flask(__name__)

APP_BOOT_ID = os.urandom(8).hex()

@app.before_request
def invalidate_on_restart():
    sid = session.get("boot_id")
    if sid is not None and sid != APP_BOOT_ID:
        session.clear()
    session["boot_id"] = APP_BOOT_ID

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///mytodo.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)


# Harden cookies a bit (flip SECURE=True when on HTTPS)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)

db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)


class Todo(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    # tie each todo to an owner
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    user = db.relationship("User", backref=db.backref("todos", lazy="dynamic"))

    def __repr__(self) -> str:
        return f"{self.sno} - {self.title}"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user_id():
    return session.get("user_id")


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/home", methods=["GET", "POST"])
@login_required
def home():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        desc = request.form.get("desc", "").strip()
        if not title or not desc:
            return Response("Title and description are required.", status=400)
        todo = Todo(title=title, desc=desc, user_id=current_user_id())
        db.session.add(todo)
        db.session.commit()
        return redirect(url_for("home"))

    all_todo = (
        Todo.query.filter_by(user_id=current_user_id())
        .order_by(Todo.date_created.desc())
        .all()
    )
    return render_template("index.html", allTodo=all_todo)


@app.route("/update/<int:sno>", methods=["GET", "POST"])
@login_required
def update(sno):
    todo = Todo.query.get_or_404(sno)
    if todo.user_id != current_user_id():
        abort(403)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        desc = request.form.get("desc", "").strip()
        if not title or not desc:
            return Response("Title and description are required.", status=400)
        todo.title = title
        todo.desc = desc
        db.session.commit()
        return redirect(url_for("home"))

    return render_template("update.html", todo=todo)


# delete should be POST-only to avoid CSRF via links
@app.route("/delete/<int:sno>", methods=["POST"])
@login_required
def delete(sno):
    todo = Todo.query.get_or_404(sno)
    if todo.user_id != current_user_id():
        abort(403)
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for("home"))


@app.route("/about")
def about():
    return "Contact us"


@app.route("/", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            session["user"] = user.username
            return redirect(url_for("home"))
        return Response("Invalid creds", status=401)

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not password:
            return Response("Username & password required", status=400)
        if User.query.filter_by(username=username).first():
            return Response("Username already taken", status=409)

        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()

        # log in and go home
        session["user_id"] = user.id
        session["user"] = user.username
        return redirect(url_for("home"))

    return render_template("signup.html")


# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # optional: seed a dev admin once (enable by setting SEED_ADMIN=1)
        if os.environ.get("SEED_ADMIN") == "1" and not User.query.filter_by(username="admin").first():
            db.session.add(User(username="admin", password_hash=generate_password_hash("change-me-now")))
            db.session.commit()

    # enable with: FLASK_DEBUG=1 python app.py
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")