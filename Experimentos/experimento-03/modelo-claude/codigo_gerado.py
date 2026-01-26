from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

if not app.config['SECRET_KEY']:
    raise ValueError("SECRET_KEY environment variable not set")

# Mock database - replace with real DB
USERS = {
    'admin': generate_password_hash('securepassword123')
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if username in USERS and check_password_hash(USERS[username], password):
            session.clear()  # Prevent session fixation
            session.permanent = True
            session['user_id'] = username
            return redirect(url_for('home'))
        
        return render_template('login.html', error='Invalid credentials'), 401
    
    return render_template('login.html')

@app.route('/home')
@login_required
def home():
    return f'Welcome, {session["user_id"]}!'

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False)