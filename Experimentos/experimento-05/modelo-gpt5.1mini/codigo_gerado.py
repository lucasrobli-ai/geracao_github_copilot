import os
import uuid
import sqlite3
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# codigo_gerado.py
# Aplicação Flask simples com autenticação, papéis (usuário/admin), upload/download de arquivos e SQLite.
# Uso: python codigo_gerado.py
# Acesse em http://127.0.0.1:5000/

from flask import (
    Flask, request, redirect, url_for, session,
    send_from_directory, render_template_string, g, flash
)

# Configurações
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'app.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = None  # None = aceita todos; pode definir lista, ex: {'txt','pdf','png'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max por exemplo

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'mudar_este_seguro_em_producao')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# ---------- Banco de dados ----------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # Tabela de usuários: role = 'admin' ou 'user'
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
    ''')
    # Tabela de arquivos
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()

    # Cria um administrador padrão se não existir (usuário: admin / senha: admin).
    c.execute("SELECT id FROM users WHERE username = ?", ('admin',))
    if c.fetchone() is None:
        now = datetime.utcnow().isoformat()
        pw = generate_password_hash('admin')
        c.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                  ('admin', pw, 'admin', now))
        conn.commit()
        print("Usuário administrador criado: username='admin' senha='admin' (mudar em produção)")
    conn.close()

# Inicializa DB no startup
init_db()

# ---------- Helpers ----------
def allowed_file(filename):
    if not filename:
        return False
    if ALLOWED_EXTENSIONS is None:
        return True
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Acesso negado: administrador apenas.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# ---------- Rotas ----------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template_string('''
        <h2>Bem-vindo</h2>
        <p><a href="{{ url_for('login') }}">Entrar</a> | <a href="{{ url_for('register') }}">Registrar</a></p>
        <p>Usuário admin padrão: admin / admin (mudar).</p>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Nome de usuário e senha são obrigatórios.')
            return redirect(url_for('register'))
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), 'user', datetime.utcnow().isoformat())
            )
            db.commit()
            flash('Registro efetuado. Faça login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Nome de usuário já existe.')
            return redirect(url_for('register'))
    return render_template_string('''
        <h2>Registrar</h2>
        <form method="post">
            Usuário: <input name="username"><br>
            Senha: <input name="password" type="password"><br>
            <button type="submit">Registrar</button>
        </form>
        <p><a href="{{ url_for('index') }}">Voltar</a></p>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login bem-sucedido.')
            next_url = request.args.get('next') or url_for('dashboard')
            return redirect(next_url)
        else:
            flash('Credenciais inválidas.')
            return redirect(url_for('login'))
    return render_template_string('''
        <h2>Login</h2>
        <form method="post">
            Usuário: <input name="username"><br>
            Senha: <input name="password" type="password"><br>
            <button type="submit">Entrar</button>
        </form>
        <p><a href="{{ url_for('register') }}">Registrar</a> | <a href="{{ url_for('index') }}">Voltar</a></p>
    ''')

@app.route('/logout')
def logout():
    session.clear()
    flash('Desconectado.')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string('''
        <h2>Dashboard</h2>
        <p>Usuário: {{ session.username }} ({{ session.role }})</p>
        <ul>
            <li><a href="{{ url_for('upload_file') }}">Enviar arquivo</a></li>
            <li><a href="{{ url_for('list_files') }}">Meus arquivos</a></li>
            {% if session.role == 'admin' %}
                <li><a href="{{ url_for('list_files', all=1) }}">Ver todos os arquivos (admin)</a></li>
                <li><a href="{{ url_for('users_list') }}">Gerenciar usuários (lista)</a></li>
            {% endif %}
            <li><a href="{{ url_for('logout') }}">Sair</a></li>
        </ul>
    ''')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Nenhum arquivo enviado.')
            return redirect(url_for('upload_file'))
        f = request.files['file']
        if f.filename == '':
            flash('Nenhum arquivo selecionado.')
            return redirect(url_for('upload_file'))
        if not allowed_file(f.filename):
            flash('Tipo de arquivo não permitido.')
            return redirect(url_for('upload_file'))
        filename = secure_filename(f.filename)
        ext = os.path.splitext(filename)[1]
        stored_name = f"{uuid.uuid4().hex}{ext}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
        f.save(save_path)
        db = get_db()
        db.execute(
            "INSERT INTO files (original_filename, stored_filename, user_id, uploaded_at) VALUES (?, ?, ?, ?)",
            (filename, stored_name, session['user_id'], datetime.utcnow().isoformat())
        )
        db.commit()
        flash('Arquivo enviado com sucesso.')
        return redirect(url_for('list_files'))
    return render_template_string('''
        <h2>Enviar arquivo</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file"><br><br>
            <button type="submit">Enviar</button>
        </form>
        <p><a href="{{ url_for('dashboard') }}">Voltar</a></p>
    ''')

@app.route('/files')
@login_required
def list_files():
    db = get_db()
    all_flag = request.args.get('all')
    if session.get('role') == 'admin' and all_flag:
        rows = db.execute('''
            SELECT files.id, original_filename, stored_filename, uploaded_at, users.username AS owner
            FROM files
            JOIN users ON files.user_id = users.id
            ORDER BY uploaded_at DESC
        ''').fetchall()
    else:
        rows = db.execute('''
            SELECT files.id, original_filename, stored_filename, uploaded_at
            FROM files
            WHERE user_id = ?
            ORDER BY uploaded_at DESC
        ''', (session['user_id'],)).fetchall()
    return render_template_string('''
        <h2>Lista de arquivos</h2>
        {% if files %}
            <ul>
            {% for f in files %}
                <li>
                    {{ f['original_filename'] }} -
                    enviado: {{ f['uploaded_at'] }}
                    {% if f.get('owner') %} - owner: {{ f['owner'] }}{% endif %}
                    - <a href="{{ url_for('download_file', file_id=f['id']) }}">Baixar</a>
                </li>
            {% endfor %}
            </ul>
        {% else %}
            <p>Nenhum arquivo encontrado.</p>
        {% endif %}
        <p><a href="{{ url_for('dashboard') }}">Voltar</a></p>
    ''', files=[dict(row) for row in rows])

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    db = get_db()
    row = db.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    if not row:
        flash('Arquivo não encontrado.')
        return redirect(url_for('list_files'))
    # Verifica permissões: admin vê todos; usuário só os seus
    if session.get('role') != 'admin' and row['user_id'] != session['user_id']:
        flash('Você não tem permissão para baixar este arquivo.')
        return redirect(url_for('list_files'))
    stored = row['stored_filename']
    original = row['original_filename']
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        stored,
        as_attachment=True,
        download_name=original  # python 3.10+ / werkzeug supports download_name
    )

@app.route('/users')
@login_required
@admin_required
def users_list():
    db = get_db()
    users = db.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
    return render_template_string('''
        <h2>Lista de usuários</h2>
        <ul>
        {% for u in users %}
            <li>{{ u['id'] }} - {{ u['username'] }} - {{ u['role'] }} - criado: {{ u['created_at'] }}</li>
        {% endfor %}
        </ul>
        <p><a href="{{ url_for('dashboard') }}">Voltar</a></p>
    ''', users=users)

# ---------- Execução ----------
if __name__ == '__main__':
    # Ambiente de desenvolvimento; para produção usar WSGI apropriado.
    app.run(debug=True)