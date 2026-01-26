from flask import Flask, g, request, redirect, url_for, session, render_template_string
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

app = Flask(__name__)
# Use an environment variable for the secret key in production
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change')

# ---------- Database helpers ----------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    db.commit()

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# ---------- Auth helpers ----------
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped_view

# ---------- Routes ----------
INDEX_HTML = """
<h2>Bem-vindo</h2>
<p><a href="{{ url_for('login') }}">Login</a> | <a href="{{ url_for('register') }}">Registrar</a></p>
"""

LOGIN_HTML = """
<h2>Login</h2>
<form method="post">
  <label>Usuário: <input name="username"></label><br>
  <label>Senha: <input name="password" type="password"></label><br>
  <button type="submit">Entrar</button>
</form>
<p>{{ error }}</p>
<p><a href="{{ url_for('register') }}">Criar conta</a></p>
"""

REGISTER_HTML = """
<h2>Registrar</h2>
<form method="post">
  <label>Usuário: <input name="username"></label><br>
  <label>Senha: <input name="password" type="password"></label><br>
  <button type="submit">Registrar</button>
</form>
<p>{{ error }}</p>
<p><a href="{{ url_for('login') }}">Já tenho conta</a></p>
"""

HOME_HTML = """
<h2>Home</h2>
<p>Olá, {{ username }}! Você está autenticado.</p>
<p><a href="{{ url_for('logout') }}">Logout</a></p>
"""

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/register', methods=('GET', 'POST'))
def register():
    error = ''
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        if not username or not password:
            error = 'Usuário e senha são obrigatórios.'
        else:
            db = get_db()
            try:
                pw_hash = generate_password_hash(password)
                db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
                db.commit()
                # Log the user in after registration
                cur = db.execute('SELECT id FROM users WHERE username = ?', (username,))
                user = cur.fetchone()
                session['user_id'] = user['id']
                session['username'] = username
                return redirect(url_for('home'))
            except sqlite3.IntegrityError:
                error = 'Usuário já existe.'
    return render_template_string(REGISTER_HTML, error=error)

@app.route('/login', methods=('GET', 'POST'))
def login():
    error = ''
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        db = get_db()
        cur = db.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        if user is None or not check_password_hash(user['password_hash'], password):
            error = 'Usuário ou senha inválidos.'
        else:
            session['user_id'] = user['id']
            session['username'] = username
            # Após autenticação, redireciona para /home
            return redirect(url_for('home'))
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/home')
@login_required
def home():
    return render_template_string(HOME_HTML, username=session.get('username'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Initialize DB and run
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(port=5002)
    



