from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Troque por uma chave secreta forte

# Simulação de "banco de dados" em memória
users_db = {}

# Templates simples
login_template = '''
    <form method="post">
        Usuário: <input type="text" name="username"><br>
        Senha: <input type="password" name="password"><br>
        <input type="submit" value="Entrar">
    </form>
    <a href="/register">Registrar</a>
    {{ message }}
'''

register_template = '''
    <form method="post">
        Usuário: <input type="text" name="username"><br>
        Senha: <input type="password" name="password"><br>
        <input type="submit" value="Registrar">
    </form>
    <a href="/login">Login</a>
    {{ message }}
'''

home_template = '''
    <h1>Bem-vindo, {{ username }}!</h1>
    <a href="/logout">Sair</a>
'''

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users_db:
            message = 'Usuário já existe.'
        else:
            users_db[username] = generate_password_hash(password)
            flash('Registrado com sucesso! Faça login.')
            return redirect(url_for('login'))
    return render_template_string(register_template, message=message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_hash = users_db.get(username)
        if user_hash and check_password_hash(user_hash, password):
            session['user'] = username
            return redirect(url_for('home'))
        else:
            message = 'Usuário ou senha inválidos.'
    return render_template_string(login_template, message=message)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    return render_template_string(home_template, username=session['user'])

if __name__ == '__main__':
    app.run(debug=True, port=5001)
    
    
    
