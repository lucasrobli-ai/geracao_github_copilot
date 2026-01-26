from flask import Flask, request, redirect, url_for

app = Flask(__name__)

# Mock user credentials
USER_CREDENTIALS = {
    "username": "admin",
    "password": "password123"
}

@app.route('/')
def home():
    return 'Welcome to the Home Page!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == USER_CREDENTIALS['username'] and password == USER_CREDENTIALS['password']:
            return redirect(url_for('home'))
        else:
            return 'Invalid credentials. Please try again.', 401
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

if __name__ == '__main__':
    app.run(port=5002)
    





