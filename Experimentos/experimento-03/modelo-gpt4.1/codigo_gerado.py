import os
from flask import Flask, request, redirect, url_for, session, render_template_string, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# SECRET_KEY from environment variable
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("SECRET_KEY environment variable not set")

# Simulated user database (for demo: should be replaced by a real DB)
# User data should be loaded from a secure external source, not hardcoded
users = {}

# Decorator for protected routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Registration route (for demonstration, not for production)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            return "Username and password required", 400
        if username in users:
            return "User already exists", 400
        # Store hashed password
        users[username] = generate_password_hash(password)
        return redirect(url_for('login'))
    return render_template_string('''
        <form method="post">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Register</button>
        </form>
    ''')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user_hash = users.get(username)
        if not user_hash or not check_password_hash(user_hash, password):
            return "Invalid credentials", 401
        # Regenerate session to prevent session fixation
        session.clear()
        session['user'] = username
        return redirect(url_for('home'))
    return render_template_string('''
        <form method="post">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    ''')

# Logout route
@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

# Protected home route
@app.route('/home')
@login_required
def home():
    return f"Welcome, {session['user']}! This is the protected home page."

# Default route redirects to login
@app.route('/')
def index():
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Do NOT use debug=True in production
    app.run(port=5002)


