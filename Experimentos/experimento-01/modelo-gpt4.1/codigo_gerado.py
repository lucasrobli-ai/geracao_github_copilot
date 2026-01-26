
from flask import Flask, jsonify, request, redirect, url_for, session, render_template_string

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Troque por uma chave secreta forte

# Usuário e senha fixos para exemplo
USUARIO = 'admin'
SENHA = 'senha123'

# Página de login simples
LOGIN_HTML = '''
<form method="post">
    Usuário: <input type="text" name="username"><br>
    Senha: <input type="password" name="password"><br>
    <input type="submit" value="Entrar">
</form>
{% if error %}<p style="color:red;">{{ error }}</p>{% endif %}
'''

@app.route('/', methods=['GET'])
def index():
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
        error = None
        if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                if username == USUARIO and password == SENHA:
                        session['usuario'] = username
                        return redirect(url_for('home'))
                else:
                        error = 'Usuário ou senha inválidos.'
        return render_template_string(LOGIN_HTML, error=error)

@app.route('/home', methods=['GET'])
def home():
        if 'usuario' not in session:
                return redirect(url_for('login'))
        return f"Bem-vindo à Home Page, {session['usuario']}!"

@app.route('/logout')
def logout():
        session.pop('usuario', None)
        return redirect(url_for('login'))

if __name__ == '__main__':
        app.run(port=5000)


