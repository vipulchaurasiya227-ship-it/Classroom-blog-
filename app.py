import os
import hashlib
import secrets
import smtplib
import sqlite3
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

import requests
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATABASE = "/tmp/classroom_blog.db" if os.environ.get("VERCEL") else os.path.join(BASE_DIR, "classroom_blog.db")
DATABASE = os.environ.get("DATABASE_PATH", DEFAULT_DATABASE)
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

FALLBACK_TOPICS = [
    "A small change that could improve our school",
    "The most useful thing I learned this month",
    "Should students have more choice in what they study?",
    "A local place everyone should visit",
    "How technology changes the way we learn",
    "An unsung person who makes our community better",
    "What makes a classroom feel welcoming?",
    "A book, film, or song that taught me something",
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            category TEXT NOT NULL,
            tags TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            author_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (author_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL,
            category TEXT NOT NULL,
            source TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "email" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if db.execute("SELECT id FROM users WHERE username = ?", ("teacher",)).fetchone() is None:
        db.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ("teacher", os.environ.get("TEACHER_EMAIL"), generate_password_hash("teacher123"), "teacher", now()),
        )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            otp_hash TEXT,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            verified_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    reset_columns = {row["name"] for row in db.execute("PRAGMA table_info(password_reset_tokens)").fetchall()}
    if "otp_hash" not in reset_columns:
        db.execute("ALTER TABLE password_reset_tokens ADD COLUMN otp_hash TEXT")
    if "verified_at" not in reset_columns:
        db.execute("ALTER TABLE password_reset_tokens ADD COLUMN verified_at TEXT")
    db.commit()


def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def send_password_reset_email(email, otp):
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("SMTP_FROM", username)
    if not all((host, username, password, sender)):
        raise RuntimeError("SMTP settings are not configured")
    message = EmailMessage()
    message["Subject"] = "Your Classroom Voices password reset code"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Your password reset code is: {otp}\n\n"
        "This code expires in 10 minutes. Enter it on the Classroom Voices password recovery page.\n\n"
        "If you did not request this, you can ignore this email."
    )
    smtp_class = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
    with smtp_class(host, port, timeout=20) as smtp:
        if port != 465:
            smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(message)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def teacher_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "teacher":
            flash("Only teachers can moderate posts.", "warning")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


@app.before_request
def load_user():
    user_id = session.get("user_id")
    g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone() if user_id else None


@app.route("/")
def index():
    db = get_db()
    query = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    sql = """
        SELECT posts.*, users.username
        FROM posts JOIN users ON users.id = posts.author_id
        WHERE posts.status = 'approved'
    """
    params = []
    if query:
        sql += " AND (posts.title LIKE ? OR posts.body LIKE ? OR posts.tags LIKE ?)"
        params.extend([f"%{query}%"] * 3)
    if category:
        sql += " AND posts.category = ?"
        params.append(category)
    sql += " ORDER BY posts.created_at DESC"
    posts = db.execute(sql, params).fetchall()
    my_pending_posts = []
    if g.user:
        my_pending_posts = db.execute(
            "SELECT * FROM posts WHERE author_id = ? AND status = 'pending' ORDER BY created_at DESC",
            (g.user["id"],),
        ).fetchall()
    categories = db.execute("SELECT DISTINCT category FROM posts WHERE status = 'approved' ORDER BY category").fetchall()
    return render_template(
        "index.html",
        posts=posts,
        my_pending_posts=my_pending_posts,
        categories=categories,
        query=query,
        selected_category=category,
    )


@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if len(username) < 3 or "@" not in email or len(password) < 6:
            flash("Enter a username, a valid email address, and a password of 6+ characters.", "warning")
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, email, generate_password_hash(password), now()),
                )
                db.commit()
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "warning")
    return render_template("auth.html", title="Create account", action="register")


@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (request.form.get("username", "").strip(),)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(request.args.get("next") or url_for("index"))
        flash("Incorrect username or password.", "warning")
    return render_template("auth.html", title="Log in", action="login")


@app.route("/forgot-password", methods=("GET", "POST"))
def forgot_password():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip().lower()
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE lower(username) = ? OR lower(email) = ?",
            (identifier, identifier),
        ).fetchone()
        if user and user["email"]:
            reset_token = secrets.token_urlsafe(32)
            otp = f"{secrets.randbelow(1_000_000):06d}"
            token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
            otp_hash = hashlib.sha256(otp.encode()).hexdigest()
            expires_at = (datetime.utcnow() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
            db.execute("DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL", (user["id"],))
            db.execute(
                "INSERT INTO password_reset_tokens (user_id, token_hash, otp_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
                (user["id"], token_hash, otp_hash, expires_at, now()),
            )
            db.commit()
            session["password_reset_id"] = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            try:
                send_password_reset_email(user["email"], otp)
            except (OSError, smtplib.SMTPException, RuntimeError) as error:
                app.logger.error("Password reset email failed: %s", error)
                flash("We could not send the reset email. Check the email service configuration and try again.", "warning")
                return redirect(url_for("forgot_password"))
            flash("A six-digit reset code was sent to your email address.", "success")
            return redirect(url_for("verify_otp"))
    return render_template("auth.html", title="Forgot password", action="forgot_password")


@app.route("/verify-otp", methods=("GET", "POST"))
def verify_otp():
    reset_id = session.get("password_reset_id")
    db = get_db()
    reset = db.execute(
        "SELECT * FROM password_reset_tokens WHERE id = ? AND used_at IS NULL AND expires_at > ?",
        (reset_id, now()),
    ).fetchone() if reset_id else None
    if reset is None:
        flash("Request a new password reset code.", "warning")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if hashlib.sha256(otp.encode()).hexdigest() != reset["otp_hash"]:
            flash("That code is incorrect or expired.", "warning")
        else:
            db.execute("UPDATE password_reset_tokens SET verified_at = ? WHERE id = ?", (now(), reset["id"]))
            db.commit()
            return redirect(url_for("reset_password_form"))
    return render_template("auth.html", title="Enter reset code", action="verify_otp")


@app.route("/reset-password", methods=("GET", "POST"))
def reset_password_form():
    reset_id = session.get("password_reset_id")
    reset = get_db().execute(
        "SELECT * FROM password_reset_tokens WHERE id = ? AND verified_at IS NOT NULL AND used_at IS NULL AND expires_at > ?",
        (reset_id, now()),
    ).fetchone() if reset_id else None
    if reset is None:
        flash("Verify a valid reset code first.", "warning")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")
        if len(password) < 6 or password != confirmation:
            flash("Passwords must match and contain at least 6 characters.", "warning")
        else:
            db = get_db()
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(password), reset["user_id"]))
            db.execute("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?", (now(), reset["id"]))
            db.commit()
            session.pop("password_reset_id", None)
            flash("Your password has been updated. You can now log in.", "success")
            return redirect(url_for("login"))
    return render_template("auth.html", title="Set a new password", action="reset_password")


@app.route("/reset-password/<token>", methods=("GET", "POST"))
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db = get_db()
    reset = db.execute(
        "SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        (token_hash, now()),
    ).fetchone()
    if reset is None:
        flash("This password reset link is invalid or expired.", "warning")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")
        if len(password) < 6 or password != confirmation:
            flash("Passwords must match and contain at least 6 characters.", "warning")
        else:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(password), reset["user_id"]))
            db.execute("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?", (now(), reset["id"]))
            db.commit()
            flash("Your password has been updated. You can now log in.", "success")
            return redirect(url_for("login"))
    return render_template("auth.html", title="Set a new password", action="reset_password")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/post/new", methods=("GET", "POST"))
@login_required
def new_post():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        category = request.form.get("category", "General").strip() or "General"
        tags = request.form.get("tags", "").strip()
        if not title or not body:
            flash("Title and story content are required.", "warning")
        else:
            db = get_db()
            status = "approved" if g.user["role"] == "teacher" else "pending"
            db.execute(
                "INSERT INTO posts (title, body, category, tags, status, author_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (title, body, category, tags, status, g.user["id"], now(), now()),
            )
            db.commit()
            flash(
                "Your post was published."
                if status == "approved"
                else "Your post was sent for teacher review. It will appear publicly after approval.",
                "success",
            )
            return redirect(url_for("index"))
    return render_template("post_form.html", post=None)


@app.route("/post/<int:post_id>")
def post_detail(post_id):
    db = get_db()
    post = db.execute(
        "SELECT posts.*, users.username FROM posts JOIN users ON users.id = posts.author_id WHERE posts.id = ?",
        (post_id,),
    ).fetchone()
    if post is None or (post["status"] != "approved" and (g.user is None or (g.user["id"] != post["author_id"] and g.user["role"] != "teacher"))):
        return render_template("message.html", title="Post not found", message="This post is not available."), 404
    comments = db.execute(
        "SELECT comments.*, users.username FROM comments JOIN users ON users.id = comments.author_id WHERE post_id = ? ORDER BY comments.created_at",
        (post_id,),
    ).fetchall()
    return render_template("post_detail.html", post=post, comments=comments)


@app.route("/post/<int:post_id>/comment", methods=("POST",))
@login_required
def add_comment(post_id):
    body = request.form.get("body", "").strip()
    if body:
        db = get_db()
        db.execute("INSERT INTO comments (post_id, author_id, body, created_at) VALUES (?, ?, ?, ?)", (post_id, g.user["id"], body, now()))
        db.commit()
    return redirect(url_for("post_detail", post_id=post_id))


@app.route("/teacher")
@teacher_required
def teacher_dashboard():
    posts = get_db().execute(
        "SELECT posts.*, users.username FROM posts JOIN users ON users.id = posts.author_id WHERE posts.status = 'pending' ORDER BY posts.created_at"
    ).fetchall()
    return render_template("teacher.html", posts=posts)


@app.route("/teacher/post/<int:post_id>/<action>", methods=("POST",))
@teacher_required
def moderate_post(post_id, action):
    status = {"approve": "approved", "reject": "rejected"}.get(action)
    if status is None:
        return redirect(url_for("teacher_dashboard"))
    db = get_db()
    db.execute("UPDATE posts SET status = ?, updated_at = ? WHERE id = ?", (status, now(), post_id))
    db.commit()
    flash(f"Post {status}.", "success")
    return redirect(url_for("teacher_dashboard"))


def generate_topic(category):
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    endpoint = os.environ.get("OPENAI_API_URL", "https://api.openai.com/v1/chat/completions")
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    response = requests.post(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": model,
            "temperature": 0.9,
            "messages": [
                {"role": "system", "content": "Create one original, age-appropriate classroom blog writing prompt. Return only the prompt."},
                {"role": "user", "content": f"Create a prompt about {category or 'any school-safe subject'}."},
            ],
        },
        timeout=20,
    )
    response.raise_for_status()
    data = response.json()
    topic = data["choices"][0]["message"]["content"].strip()
    return topic if topic else None


@app.route("/api/topic")
@login_required
def api_topic():
    category = request.args.get("category", "any school-safe subject")
    source = "external-ai"
    try:
        topic = generate_topic(category)
    except (requests.RequestException, KeyError, ValueError) as error:
        app.logger.warning("Topic service unavailable: %s", error)
        topic = None
    if not topic:
        source = "local-fallback"
        topic = FALLBACK_TOPICS[get_db().execute("SELECT COUNT(*) AS count FROM topics").fetchone()["count"] % len(FALLBACK_TOPICS)]
    db = get_db()
    db.execute("INSERT INTO topics (topic, category, source, created_at) VALUES (?, ?, ?, ?)", (topic, category, source, now()))
    db.commit()
    return {"topic": topic, "source": source}


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
    )
