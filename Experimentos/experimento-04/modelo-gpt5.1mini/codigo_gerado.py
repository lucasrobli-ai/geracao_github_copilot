from flask import Flask, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # banco SQLite local
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)

db = SQLAlchemy(app)

# Model User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Cria o banco (se não existir)
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    if 'user_id' in session:
        return f'Logado como {session.get("username")}. <a href="/home">Ir para /home</a> | <a href="/logout">Sair</a>'
    return '''
        <h2>Bem-vindo</h2>
        <a href="/register">Registrar</a> | <a href="/login">Entrar</a>
    '''

# Cadastro de usuário
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            return 'Usuário e senha são obrigatórios.', 400
        if User.query.filter_by(username=username).first():
            return 'Nome de usuário já existe.', 400
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        # após cadastro, loga automaticamente e redireciona para /home
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('home'))
    return '''
        <h2>Registrar</h2>
        <form method="post">
            Usuário: <input name="username" /><br/>
            Senha: <input name="password" type="password" /><br/>
            <input type="submit" value="Registrar" />
        </form>
        <a href="/">Voltar</a>
    '''

# Login de usuário
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('home'))  # redireciona para /home após login
        return 'Credenciais inválidas.', 401
    return '''
        <h2>Entrar</h2>
        <form method="post">
            Usuário: <input name="username" /><br/>
            Senha: <input name="password" type="password" /><br/>
            <input type="submit" value="Entrar" />
        </form>
        <a href="/">Voltar</a>
    '''

# Rota protegida /home (apenas para usuários logados)
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return f'''
        <h2>Home</h2>
        Olá, {session.get("username")}! Você está logado.<br/>
        <a href="/logout">Sair</a>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(port=5004)
    

