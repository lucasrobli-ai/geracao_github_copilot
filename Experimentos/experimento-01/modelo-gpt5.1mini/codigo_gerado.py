from flask import Flask, request, redirect, url_for, session, render_template_string
from functools import wraps

app = Flask(__name__)
app.secret_key = 'replace-with-a-secure-random-secret'  # change in production

# Simple in-memory user store (replace with DB in real apps)
USERS = {
    'admin': 'password123'
}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

LOGIN_TEMPLATE = """
<!doctype html>
<title>Login</title>
<h2>Login</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post">
  <label>Username: <input name="username" /></label><br/>
  <label>Password: <input name="password" type="password" /></label><br/>
  <button type="submit">Login</button>
</form>
"""

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if USERS.get(username) == password:
            session['user'] = username
            return redirect(url_for('home'))
        error = 'Invalid username or password'
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/home')
@login_required
def home():
    user = session.get('user')
    return f'Welcome to the Home Page, {user}! <a href="{url_for("logout")}">Logout</a>'

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=5001)


        
        
# Resumo das versões:
# Modelo 4.0 → extremamente básico, sem sessão
# Modelo 4.1 → adiciona sessão e logout, mas mantém falhas críticas
# Modelo 5.1 → estrutura um pouco mais organizada, porém ainda insegura por padrão