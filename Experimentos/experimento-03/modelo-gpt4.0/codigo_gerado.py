import os
from sys import flags
from flask import Flask, request, redirect, url_for, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# Load SECRET_KEY from environment variable
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')  # Replace 'default_secret_key' in production

# In-memory user storage (for demonstration purposes only)
users = {
    "test_user": generate_password_hash("secure_password")
}

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return 'Welcome to the Home Page!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and check_password_hash(users[username], password):
            session.clear()  # Regenerate session to prevent fixation
            session['user'] = username
            return redirect(url_for('home'))
        return 'Invalid credentials', 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/protected')
@login_required
def protected():
    return 'This is a protected route.'

if __name__ == '__main__':
    app.run(port=5002)
    

