from functools import wraps
from flask import Flask, request, session, redirect, url_for, abort, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

# Ensure SECRET_KEY is provided via environment
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable must be set")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Enable secure cookies only when explicitly requested (set SESSION_COOKIE_SECURE=1)
    SESSION_COOKIE_SECURE=(os.getenv("SESSION_COOKIE_SECURE", "0") == "1"),
)

DB_PATH = os.getenv("AUTH_DB_PATH", "auth.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"
        )
        conn.commit()
    finally:
        conn.close()


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


# Simple templates (for academic/demo purposes)
_LOGIN_HTML = """
<!doctype html>
<title>Login</title>
<h1>Login</h1>
<form method="post">
  <label>Username <input name="username" required></label><br>
  <label>Password <input type="password" name="password" required></label><br>
  <button type="submit">Login</button>
</form>
<p>Or <a href="{{ url_for('register') }}">register</a></p>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
"""

_REGISTER_HTML = """
<!doctype html>
<title>Register</title>
<h1>Register</h1>
<form method="post">
  <label>Username <input name="username" required></label><br>
  <label>Password <input type="password" name="password" required></label><br>
  <button type="submit">Register</button>
</form>
<p>Already have an account? <a href="{{ url_for('login') }}">login</a></p>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
"""    


@app.route("/")
def index():
    return "Welcome. Please /login or /register"


@app.route("/register", methods=["GET", "POST"])
def register():
    # Registration provided for academic/demo use; no credentials are hardcoded.
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            error = "Missing username or password"
        else:
            password_hash = generate_password_hash(password)  # PBKDF2 by werkzeug
            conn = get_db_connection()
            try:
                try:
                    conn.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, password_hash),
                    )
                    conn.commit()
                except sqlite3.IntegrityError:
                    error = "Username already exists"
            finally:
                conn.close()
            if not error:
                return redirect(url_for("login"))
    return render_template_string(_REGISTER_HTML, error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            error = "Missing credentials"
        else:
            conn = get_db_connection()
            try:
                row = conn.execute(
                    "SELECT id, password_hash FROM users WHERE username = ?", (username,)
                ).fetchone()
            finally:
                conn.close()

            if row and check_password_hash(row["password_hash"], password):
                # Regenerate session to mitigate session fixation
                session.clear()
                session.permanent = True
                session["user_id"] = int(row["id"])
                return redirect(url_for("home"))
            else:
                # Generic error message to avoid user enumeration
                error = "Invalid username or password"
    return render_template_string(_LOGIN_HTML, error=error)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/home")
@login_required
def home():
    return "You are authenticated and on /home"


if __name__ == "__main__":
    init_db()
    # Do NOT enable debug=True in production/academic assessments
    app.run(port=5002)
    

    

# Versão	Postura de Segurança
# 4.0	    Insegura (falhas críticas)
# 4.1	    Intermediária (melhorou, mas frágil)
# 5.1	    Boa (Possui alguns riscos e falta ausência de controles avançados)