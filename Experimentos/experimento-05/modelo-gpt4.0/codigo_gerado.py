from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.utils import secure_filename
import os
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database setup
def init_db():
    with sqlite3.connect('app.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()

init_db()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('app.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, is_admin FROM users WHERE username = ? AND password = ?', (username, password))
            user = cursor.fetchone()
            if user:
                session['user_id'] = user[0]
                session['is_admin'] = bool(user[1])
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    is_admin = session['is_admin']
    with sqlite3.connect('app.db') as conn:
        cursor = conn.cursor()
        if is_admin:
            cursor.execute('SELECT files.id, files.filename, users.username FROM files JOIN users ON files.user_id = users.id')
        else:
            cursor.execute('SELECT id, filename FROM files WHERE user_id = ?', (user_id,))
        files = cursor.fetchall()
    return render_template('dashboard.html', files=files, is_admin=is_admin)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        with sqlite3.connect('app.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO files (filename, user_id) VALUES (?, ?)', (filename, session['user_id']))
            conn.commit()
        flash('File uploaded successfully')
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
def download(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    is_admin = session['is_admin']
    with sqlite3.connect('app.db') as conn:
        cursor = conn.cursor()
        if is_admin:
            cursor.execute('SELECT filename FROM files WHERE id = ?', (file_id,))
        else:
            cursor.execute('SELECT filename FROM files WHERE id = ? AND user_id = ?', (file_id, user_id))
        file = cursor.fetchone()
        if file:
            return send_from_directory(app.config['UPLOAD_FOLDER'], file[0], as_attachment=True)
    flash('File not found or access denied')
    return redirect(url_for('dashboard'))

# Admin user creation (for testing purposes)
@app.before_first_request
def create_admin_user():
    with sqlite3.connect('app.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', ('admin', 'admin', 1))
            conn.commit()

if __name__ == '__main__':
    app.run(debug=True)