import os
import sqlite3
from flask import Flask, request, redirect, url_for, render_template_string, session, send_from_directory, abort, g
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Configurações
UPLOAD_FOLDER = 'uploads'
DATABASE = 'app.db'
SECRET_KEY = 'sua_chave_secreta'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY

# Templates simples
LOGIN_TEMPLATE = '''
<h2>Login</h2>
<form method="post">
    Usuário: <input name="username"><br>
    Senha: <input name="password" type="password"><br>
    <input type="submit" value="Entrar">
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
'''

UPLOAD_TEMPLATE = '''
<h2>Bem-vindo, {{ user['username'] }} ({{ user['role'] }})</h2>
<a href="{{ url_for('logout') }}">Sair</a>
<h3>Enviar arquivo</h3>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
<h3>Seus arquivos</h3>
<ul>
    {% for file in files %}
        <li>{{ file['filename'] }} - <a href="{{ url_for('download', file_id=file['id']) }}">Download</a></li>
    {% endfor %}
</ul>
{% if user['role'] == 'admin' %}
    <h3>Arquivos de todos os usuários</h3>
    <ul>
        {% for file in all_files %}
            <li>{{ file['filename'] }} ({{ file['username'] }}) - <a href="{{ url_for('download', file_id=file['id']) }}">Download</a></li>
        {% endfor %}
    </ul>
{% endif %}
'''

# Banco de dados
def get_db():
        if 'db' not in g:
                g.db = sqlite3.connect(DATABASE)
                g.db.row_factory = sqlite3.Row
        return g.db

@app.teardown_appcontext
def close_db(error):
        db = g.pop('db', None)
        if db:
                db.close()

def init_db():
        db = get_db()
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
        );
        ''')
        # Cria usuário admin padrão se não existir
        cur = db.execute('SELECT * FROM users WHERE username = ?', ('admin',))
        if not cur.fetchone():
                db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                                     ('admin', generate_password_hash('admin'), 'admin'))
        db.commit()

@app.before_first_request
def setup():
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        init_db()

# Autenticação
def get_user():
        user_id = session.get('user_id')
        if not user_id:
                return None
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        return user

def login_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
                if not get_user():
                        return redirect(url_for('login'))
                return f(*args, **kwargs)
        return decorated

# Rotas
@app.route('/login', methods=['GET', 'POST'])
def login():
        error = None
        if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                db = get_db()
                user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                if user and check_password_hash(user['password'], password):
                        session['user_id'] = user['id']
                        return redirect(url_for('upload'))
                else:
                        error = 'Usuário ou senha inválidos'
        return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
        session.clear()
        return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def upload():
        user = get_user()
        db = get_db()
        if request.method == 'POST':
                file = request.files.get('file')
                if file and file.filename:
                        filename = secure_filename(file.filename)
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        db.execute('INSERT INTO files (filename, user_id) VALUES (?, ?)', (filename, user['id']))
                        db.commit()
        # Listagem dos arquivos do usuário
        files = db.execute('SELECT * FROM files WHERE user_id = ?', (user['id'],)).fetchall()
        # Se admin, lista todos os arquivos
        all_files = []
        if user['role'] == 'admin':
                all_files = db.execute('''
                        SELECT files.id, files.filename, users.username
                        FROM files JOIN users ON files.user_id = users.id
                ''').fetchall()
        return render_template_string(UPLOAD_TEMPLATE, user=user, files=files, all_files=all_files)

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
        user = get_user()
        db = get_db()
        file = db.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
        if not file:
                abort(404)
        # Permissão: admin pode tudo, usuário só seus arquivos
        if user['role'] != 'admin' and file['user_id'] != user['id']:
                abort(403)
        return send_from_directory(app.config['UPLOAD_FOLDER'], file['filename'], as_attachment=True)

# Criação de usuário comum (apenas para teste, pode ser removido)
@app.route('/register', methods=['GET', 'POST'])
def register():
        error = None
        if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                db = get_db()
                try:
                        db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                                             (username, generate_password_hash(password), 'user'))
                        db.commit()
                        return redirect(url_for('login'))
                except sqlite3.IntegrityError:
                        error = 'Usuário já existe'
        return render_template_string('''
        <h2>Registrar</h2>
        <form method="post">
            Usuário: <input name="username"><br>
            Senha: <input name="password" type="password"><br>
            <input type="submit" value="Registrar">
        </form>
        {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
        ''', error=error)

if __name__ == '__main__':
        app.run(debug=True)