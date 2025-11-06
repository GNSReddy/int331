import os
from flask import Flask, request, jsonify, render_template, send_file, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import logging
from datetime import datetime

# App Configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_manager.db'
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Encryption Key
key = Fernet.generate_key()
cipher = Fernet(key)

# Logging
logging.basicConfig(filename='security.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

class FileLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(256), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Embedded Templates
BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{% block title %}Optimizing File System{% endblock %}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }

        nav {
            background-color: #333;
            padding: 1rem;
        }

        nav a {
            color: white;
            text-decoration: none;
            margin-right: 1rem;
        }

        .alert {
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }

        .alert-success {
            background-color: #d4edda;
            color: #155724;
        }

        .alert-error {
            background-color: #f8d7da;
            color: #721c24;
        }

        .container {
            max-width: 800px;
            margin: 20px auto;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }

        form {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        input, button {
            padding: 8px;
            margin: 5px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        button {
            background-color: #333;
            color: white;
            cursor: pointer;
        }

        button:hover {
            background-color: #555;
        }
    </style>
</head>
<body>
    <nav>
        <a href="{{ url_for('index') }}">Home</a>
        {% if current_user.is_authenticated %}
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('upload') }}">Upload</a>
            {% if current_user.username == 'admin' %}
                <a href="{{ url_for('get_logs') }}">Logs</a>
            {% endif %}
            <a href="{{ url_for('logout') }}">Logout</a>
        {% else %}
            <a href="{{ url_for('login') }}">Login</a>
            <a href="{{ url_for('register') }}">Register</a>
        {% endif %}
    </nav>
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', (e) => {
                    if (!form.checkValidity()) {
                        e.preventDefault();
                        e.stopPropagation();
                    }
                    form.classList.add('was-validated');
                });
            });
        });
    </script>
</body>
</html>
"""

INDEX_HTML = """
{% extends "base.html" %}
{% block title %}Home{% endblock %}
{% block content %}
<div class="container">
    <h1>Welcome to Optimizing File System</h1>
    <p>This system provides secure file storage, fast retrieval, and robust recovery mechanisms.</p>
    {% if not current_user.is_authenticated %}
        <a href="{{ url_for('login') }}" class="btn">Login</a>
        <a href="{{ url_for('register') }}" class="btn">Register</a>
    {% else %}
        <a href="{{ url_for('dashboard') }}" class="btn">Go to Dashboard</a>
    {% endif %}
</div>
{% endblock %}
"""

LOGIN_HTML = """
{% extends "base.html" %}
{% block title %}Login{% endblock %}
{% block content %}
<div class="container">
    <h1>Login</h1>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a>.</p>
</div>
{% endblock %}
"""

REGISTER_HTML = """
{% extends "base.html" %}
{% block title %}Register{% endblock %}
{% block content %}
<div class="container">
    <h1>Register</h1>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
</div>
{% endblock %}
"""

DASHBOARD_HTML = """
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<div class="container">
    <h1>Dashboard</h1>
    <p>Welcome, {{ current_user.username }}!</p>
    <a href="{{ url_for('upload') }}" class="btn">Upload File</a>
</div>
{% endblock %}
"""

UPLOAD_HTML = """
{% extends "base.html" %}
{% block title %}Upload File{% endblock %}
{% block content %}
<div class="container">
    <h1>Upload File</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <button type="submit">Upload</button>
    </form>
</div>
{% endblock %}
"""

LOGS_HTML = """
{% extends "base.html" %}
{% block title %}System Logs{% endblock %}
{% block content %}
<div class="container">
    <h1>System Logs</h1>
    <ul>
    {% for log in logs %}
        <li>{{ log.timestamp }} - User ID: {{ log.user_id }}, Action: {{ log.action }}, File: {{ log.filename }}</li>
    {% endfor %}
    </ul>
</div>
{% endblock %}
"""

# Routes
app.jinja_env.globals.update(BASE_HTML=BASE_HTML, INDEX_HTML=INDEX_HTML, LOGIN_HTML=LOGIN_HTML, REGISTER_HTML=REGISTER_HTML, DASHBOARD_HTML=DASHBOARD_HTML, UPLOAD_HTML=UPLOAD_HTML, LOGS_HTML=LOGS_HTML)

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('User already exists', 'error')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        logging.info(f"User registered: {username}")
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template_string(REGISTER_HTML)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            logging.info(f"User logged in: {user.username}")
            return redirect(url_for('dashboard'))
        logging.warning(f"Failed login attempt: {request.form['username']}")
        flash('Invalid credentials', 'error')
    return render_template_string(LOGIN_HTML)

@app.route('/logout')
@login_required
def logout():
    logging.info(f"User logged out: {current_user.username}")
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file:
            encrypted_data = cipher.encrypt(file.read())
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{current_user.id}_{file.filename}")
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            log_action(current_user.id, file.filename, "upload")
            logging.info(f"File uploaded by {current_user.username}: {file.filename}")
            flash('File uploaded successfully', 'success')
            return redirect(url_for('dashboard'))
    return render_template_string(UPLOAD_HTML)

@app.route('/download/<filename>')
@login_required
def download(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{current_user.id}_{filename}")
    if not os.path.exists(file_path):
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
    with open(file_path, 'rb') as f:
        decrypted_data = cipher.decrypt(f.read())
    download_path = f"temp_{filename}"
    with open(download_path, 'wb') as f:
        f.write(decrypted_data)
    log_action(current_user.id, filename, "download")
    logging.info(f"File downloaded by {current_user.username}: {filename}")
    return send_file(download_path, as_attachment=True, download_name=filename)

def log_action(user_id, filename, action):
    log = FileLog(user_id=user_id, filename=filename, action=action)
    db.session.add(log)
    db.session.commit()

@app.route('/logs')
@login_required
def get_logs():
    if current_user.username != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
    logs = FileLog.query.all()
    return render_template_string(LOGS_HTML, logs=logs)

# Initialize Database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)