from flask import Flask, render_template, request, redirect, session, url_for
from functools import wraps

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'

# Credenciais de exemplo (em produção, use banco de dados)
USUARIOS = {
    'user': 'senha123',
    'admin': 'admin123'
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('usuario')
        senha = request.form.get('senha')
        
        if usuario in USUARIOS and USUARIOS[usuario] == senha:
            session['usuario'] = usuario
            return redirect(url_for('home'))
        else:
            return render_template('login.html', erro='Usuário ou senha inválidos')
    
    return render_template('login.html')

@app.route('/home')
@login_required
def home():
    return f'Bem-vindo, {session["usuario"]}!'

@app.route('/')
def hello_world():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run(debug=True)