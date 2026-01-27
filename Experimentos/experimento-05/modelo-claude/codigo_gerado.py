import os
import sqlite3
from flask import Flask, request, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY, user_id INTEGER, filename TEXT, 
                  original_name TEXT, upload_date TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    conn.commit()
    conn.close()

init_db()

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        if not user or user[0] != 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# Authentication routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    
    try:
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                  (username, generate_password_hash(password), 'user'))
        conn.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('SELECT id, password, role FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    if not user or not check_password_hash(user[1], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    session['user_id'] = user[0]
    session['username'] = username
    session['role'] = user[2]
    
    return jsonify({'message': 'Login successful', 'role': user[2]}), 200

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'}), 200

# File routes
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filename = secure_filename(file.filename)
    unique_filename = f"{session['user_id']}_{datetime.now().timestamp()}_{filename}"
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
    
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('INSERT INTO files (user_id, filename, original_name, upload_date) VALUES (?, ?, ?, ?)',
              (session['user_id'], unique_filename, filename, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'File uploaded successfully'}), 201

@app.route('/files', methods=['GET'])
@login_required
def list_files():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    
    if session['role'] == 'admin':
        c.execute('''SELECT f.id, f.original_name, u.username, f.upload_date 
                     FROM files f JOIN users u ON f.user_id = u.id''')
    else:
        c.execute('''SELECT f.id, f.original_name, u.username, f.upload_date 
                     FROM files f JOIN users u ON f.user_id = u.id WHERE f.user_id = ?''',
                  (session['user_id'],))
    
    files = c.fetchall()
    conn.close()
    
    return jsonify({'files': [{'id': f[0], 'name': f[1], 'user': f[2], 'date': f[3]} for f in files]}), 200

@app.route('/download/<int:file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('SELECT user_id, filename, original_name FROM files WHERE id = ?', (file_id,))
    file_data = c.fetchone()
    conn.close()
    
    if not file_data:
        return jsonify({'error': 'File not found'}), 404
    
    if session['role'] != 'admin' and file_data[0] != session['user_id']:
        return jsonify({'error': 'Forbidden'}), 403
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data[1])
    return send_file(file_path, as_attachment=True, download_name=file_data[2])

if __name__ == '__main__':
    app.run(debug=True)