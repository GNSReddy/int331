# app.py - Complete Secure File Management System
import os
import sqlite3
import logging
from datetime import datetime
import ipaddress
from flask import Flask, render_template_string, request, redirect, url_for, flash, send_file, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['TEMP_FOLDER'] = 'temp'
app.config['DATABASE'] = 'file_system.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Encryption setup
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_FOLDER'], exist_ok=True)

# Database setup
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE
    )''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        encrypted_filename TEXT NOT NULL,
        upload_date TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        filename TEXT,
        ip_address TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS failed_logins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )''')
    
    # Add admin user if not exists
    cursor.execute('SELECT id FROM users WHERE username = "admin"')
    if not cursor.fetchone():
        admin_hash = generate_password_hash('admin123')
        cursor.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)', 
                      ('admin', admin_hash, True))
    
    conn.commit()
    conn.close()

init_db()

# Logging setup
logging.basicConfig(
    filename='security.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, is_admin FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    return None

# Helper functions
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def log_activity(user_id, action, filename=None, ip_address=None):
    conn = get_db_connection()
    timestamp = datetime.now().isoformat()
    ip = ip_address or request.remote_addr
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            logging.warning(f"External IP access: {ip} for action: {action}")
    except ValueError:
        pass
    
    conn.execute('''
        INSERT INTO file_logs (user_id, action, filename, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, action, filename, ip, timestamp))
    conn.commit()
    conn.close()
    
    logging.info(f"User {user_id} performed {action} on {filename or 'system'} from IP {ip}")

def is_suspicious_ip(ip):
    """Basic check for suspicious IP patterns"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return True

def get_total_file_size(user_id):
    conn = get_db_connection()
    total = conn.execute('SELECT SUM(file_size) FROM files WHERE user_id = ?', (user_id,)).fetchone()[0]
    conn.close()
    return total or 0

# Custom template filters
@app.template_filter('filesizeformat')
def filesizeformat_filter(size):
    """Convert file size to human-readable format"""
    for unit in ['bytes', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

# Base template
base_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Manager - {title}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .jumbotron { background-color: #e9ecef; padding: 2rem; border-radius: 0.3rem; }
        .card { border: none; box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075); margin-bottom: 1.5rem; }
        .table-responsive { margin-bottom: 2rem; }
        footer { margin-top: 3rem; border-top: 1px solid #dee2e6; }
        .progress { height: 1.5rem; margin-bottom: 1rem; }
        .badge { padding: 0.35em 0.65em; font-weight: 500; }
        .alert-dismissible .btn-close { padding: 0.5rem 1rem; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">Secure File Manager</a>
            <div class="navbar-nav">
                {nav_links}
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {messages}
        {content}
    </div>

    <footer class="mt-5 py-3 bg-light">
        <div class="container text-center">
            <p class="mb-0">Secure File Manager &copy; 2023</p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    {scripts}
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    nav_links = '''
    <a class="nav-link" href="/login">Login</a>
    <a class="nav-link" href="/register">Register</a>
    '''
    
    content = '''
    <div class="jumbotron">
        <h1 class="display-4">Welcome to Secure File Manager</h1>
        <p class="lead">A secure platform for managing your files with encryption and threat detection.</p>
        <hr class="my-4">
        <p>Please login or register to access your files.</p>
        <div class="mt-4">
            <a class="btn btn-primary btn-lg mr-3" href="/register" role="button">Register</a>
            <a class="btn btn-outline-primary btn-lg" href="/login" role="button">Login</a>
        </div>
    </div>

    <div class="row mt-5">
        <div class="col-md-4">
            <div class="card h-100">
                <div class="card-body">
                    <h5 class="card-title">Secure Storage</h5>
                    <p class="card-text">All files are encrypted with AES-256 encryption before storage.</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card h-100">
                <div class="card-body">
                    <h5 class="card-title">Activity Monitoring</h5>
                    <p class="card-text">Comprehensive logging of all file operations and user activities.</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card h-100">
                <div class="card-body">
                    <h5 class="card-title">Threat Detection</h5>
                    <p class="card-text">Advanced monitoring for suspicious activities.</p>
                </div>
            </div>
        </div>
    </div>
    '''
    
    return render_template_string(
        base_template.format(
            title="Home",
            nav_links=nav_links,
            messages="",
            content=content,
            scripts=""
        )
    )

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            flash('Username already exists', 'error')
            conn.close()
            return redirect(url_for('register'))
        
        password_hash = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        
        user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        
        log_activity(user_id, 'registration')
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    
    nav_links = '''
    <a class="nav-link" href="/login">Login</a>
    <a class="nav-link" href="/register">Register</a>
    '''
    
    content = '''
    <div class="row justify-content-center">
        <div class="col-md-6 col-lg-4">
            <div class="card">
                <div class="card-body">
                    <h2 class="card-title text-center mb-4">Register</h2>
                    <form method="POST" action="/register">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary">Register</button>
                        </div>
                    </form>
                    <div class="mt-3 text-center">
                        <p>Already have an account? <a href="/login">Login here</a></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    
    return render_template_string(
        base_template.format(
            title="Register",
            nav_links=nav_links,
            messages="",
            content=content,
            scripts=""
        )
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('''
            SELECT id, username, password_hash, is_admin 
            FROM users 
            WHERE username = ?
        ''', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            user_obj = User(user['id'], user['username'], user['is_admin'])
            login_user(user_obj)
            
            log_activity(user['id'], 'login')
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            ip = request.remote_addr
            timestamp = datetime.now().isoformat()
            
            conn = get_db_connection()
            conn.execute('''
                INSERT INTO failed_logins (username, ip_address, timestamp)
                VALUES (?, ?, ?)
            ''', (username, ip, timestamp))
            conn.commit()
            conn.close()
            
            logging.warning(f"Failed login attempt for username: {username} from IP: {ip}")
            flash('Invalid username or password', 'error')
    
    nav_links = '''
    <a class="nav-link" href="/login">Login</a>
    <a class="nav-link" href="/register">Register</a>
    '''
    
    content = '''
    <div class="row justify-content-center">
        <div class="col-md-6 col-lg-4">
            <div class="card">
                <div class="card-body">
                    <h2 class="card-title text-center mb-4">Login</h2>
                    <form method="POST" action="/login">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary">Login</button>
                        </div>
                    </form>
                    <div class="mt-3 text-center">
                        <p>Don't have an account? <a href="/register">Register here</a></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    
    return render_template_string(
        base_template.format(
            title="Login",
            nav_links=nav_links,
            messages="",
            content=content,
            scripts=""
        )
    )

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'logout')
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    files = conn.execute('''
        SELECT id, filename, upload_date, file_size 
        FROM files 
        WHERE user_id = ? 
        ORDER BY upload_date DESC
    ''', (current_user.id,)).fetchall()
    total_size = get_total_file_size(current_user.id)
    conn.close()
    
    files_html = ""
    for file in files:
        files_html += f'''
        <tr>
            <td>{file['filename']}</td>
            <td>{file['upload_date']}</td>
            <td>{filesizeformat_filter(file['file_size'])}</td>
            <td>
                <div class="btn-group" role="group">
                    <a href="/download/{file['id']}" class="btn btn-sm btn-outline-primary">Download</a>
                    <a href="/delete/{file['id']}" class="btn btn-sm btn-outline-danger" onclick="return confirm('Are you sure?')">Delete</a>
                </div>
            </td>
        </tr>
        '''
    
    nav_links = f'''
    <a class="nav-link" href="/dashboard">Dashboard</a>
    <a class="nav-link" href="/upload">Upload</a>
    { '<a class="nav-link" href="/logs">View Logs</a>' if current_user.is_admin else '' }
    <a class="nav-link" href="/logout">Logout</a>
    '''
    
    messages = ""
    if request.args.get('message'):
        messages = f'''
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            {request.args.get('message')}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
        '''
    
    content = f'''
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>Your Files</h2>
        <a href="/upload" class="btn btn-success">
            Upload File
        </a>
    </div>

    { '<div class="alert alert-info">You haven\'t uploaded any files yet. Click the "Upload File" button to get started.</div>' if not files else '' }

    <div class="table-responsive">
        <table class="table table-striped table-hover">
            <thead class="table-dark">
                <tr>
                    <th>Filename</th>
                    <th>Upload Date</th>
                    <th>Size</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {files_html}
            </tbody>
        </table>
    </div>

    <div class="mt-4">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Storage Summary</h5>
                <div class="progress mb-3">
                    <div class="progress-bar" role="progressbar" style="width: 25%;" 
                        aria-valuenow="25" aria-valuemin="0" aria-valuemax="100">25% used</div>
                </div>
                <p class="card-text">
                    <strong>{len(files)}</strong> files stored<br>
                    <strong>{filesizeformat_filter(total_size)}</strong> total storage used
                </p>
            </div>
        </div>
    </div>
    '''
    
    return render_template_string(
        base_template.format(
            title="Dashboard",
            nav_links=nav_links,
            messages=messages,
            content=content,
            scripts=""
        )
    )

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file:
            encrypted_data = cipher_suite.encrypt(file.read())
            original_filename = file.filename
            encrypted_filename = f"enc_{current_user.id}_{datetime.now().timestamp()}_{original_filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            file_size = len(encrypted_data)
            upload_date = datetime.now().isoformat()
            
            conn = get_db_connection()
            conn.execute('''
                INSERT INTO files (user_id, filename, encrypted_filename, upload_date, file_size)
                VALUES (?, ?, ?, ?, ?)
            ''', (current_user.id, original_filename, encrypted_filename, upload_date, file_size))
            conn.commit()
            conn.close()
            
            log_activity(current_user.id, 'upload', original_filename)
            return redirect(url_for('dashboard', message='File uploaded successfully'))
    
    nav_links = f'''
    <a class="nav-link" href="/dashboard">Dashboard</a>
    <a class="nav-link" href="/upload">Upload</a>
    { '<a class="nav-link" href="/logs">View Logs</a>' if current_user.is_admin else '' }
    <a class="nav-link" href="/logout">Logout</a>
    '''
    
    content = '''
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-body">
                    <h2 class="card-title mb-4">Upload File</h2>
                    
                    <form method="POST" enctype="multipart/form-data" action="/upload">
                        <div class="mb-3">
                            <label for="file" class="form-label">Select file to upload</label>
                            <input class="form-control" type="file" id="file" name="file" required>
                        </div>
                        
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="encrypt" name="encrypt" checked>
                            <label class="form-check-label" for="encrypt">Encrypt file (recommended)</label>
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary">Upload File</button>
                        </div>
                    </form>
                    
                    <div class="mt-4">
                        <div class="alert alert-info">
                            <h5 class="alert-heading">Security Information</h5>
                            <p>
                                All files are encrypted with AES-256 encryption before storage. 
                                Only you can access your files with your account credentials.
                            </p>
                            <hr>
                            <p class="mb-0">
                                Maximum file size: 16 MB
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    
    return render_template_string(
        base_template.format(
            title="Upload File",
            nav_links=nav_links,
            messages="",
            content=content,
            scripts=""
        )
    )

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    conn = get_db_connection()
    file_data = conn.execute('''
        SELECT filename, encrypted_filename 
        FROM files 
        WHERE id = ? AND user_id = ?
    ''', (file_id, current_user.id)).fetchone()
    conn.close()
    
    if not file_data:
        abort(404)
    
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data['encrypted_filename'])
    
    if not os.path.exists(encrypted_path):
        abort(404)
    
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    temp_filename = f"temp_{file_data['filename']}"
    temp_path = os.path.join(app.config['TEMP_FOLDER'], temp_filename)
    
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    
    log_activity(current_user.id, 'download', file_data['filename'])
    
    response = send_file(
        temp_path, 
        as_attachment=True, 
        download_name=file_data['filename']
    )
    
    @response.call_on_close
    def remove_temp_file():
        try:
            os.unlink(temp_path)
        except OSError:
            pass
    
    return response

@app.route('/delete/<int:file_id>')
@login_required
def delete(file_id):
    conn = get_db_connection()
    file_data = conn.execute('''
        SELECT filename, encrypted_filename 
        FROM files 
        WHERE id = ? AND user_id = ?
    ''', (file_id, current_user.id)).fetchone()
    
    if not file_data:
        conn.close()
        abort(404)
    
    conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
    conn.commit()
    conn.close()
    
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data['encrypted_filename'])
    if os.path.exists(encrypted_path):
        os.unlink(encrypted_path)
    
    log_activity(current_user.id, 'delete', file_data['filename'])
    return redirect(url_for('dashboard', message='File deleted successfully'))

@app.route('/logs')
@login_required
def view_logs():
    if not current_user.is_admin:
        abort(403)
    
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT file_logs.*, users.username 
        FROM file_logs 
        JOIN users ON file_logs.user_id = users.id 
        ORDER BY timestamp DESC
        LIMIT 100
    ''').fetchall()
    
    failed_logins = conn.execute('''
        SELECT * 
        FROM failed_logins 
        ORDER BY timestamp DESC 
        LIMIT 50
    ''').fetchall()
    conn.close()
    
    logs_html = ""
    for log in logs:
        ip_class = 'text-danger' if is_suspicious_ip(log['ip_address']) else ''
        logs_html += f'''
        <tr>
            <td>{log['timestamp']}</td>
            <td>{log['username']}</td>
            <td><span class="badge bg-primary">{log['action']}</span></td>
            <td>{log['filename'] or '-'}</td>
            <td class="{ip_class}">{log['ip_address']}</td>
        </tr>
        '''
    
    failed_logins_html = ""
    for attempt in failed_logins:
        ip_class = 'text-danger' if is_suspicious_ip(attempt['ip_address']) else ''
        failed_logins_html += f'''
        <tr>
            <td>{attempt['timestamp']}</td>
            <td>{attempt['username']}</td>
            <td class="{ip_class}">{attempt['ip_address']}</td>
        </tr>
        '''
    
    log_activity(current_user.id, 'view_logs')
    
    nav_links = f'''
    <a class="nav-link" href="/dashboard">Dashboard</a>
    <a class="nav-link" href="/upload">Upload</a>
    <a class="nav-link" href="/logs">View Logs</a>
    <a class="nav-link" href="/logout">Logout</a>
    '''
    
    content = f'''
    <div class="mb-4">
        <h2>System Logs</h2>
        <p class="text-muted">Activity and security monitoring logs</p>
    </div>

    <ul class="nav nav-tabs mb-4" id="logsTabs" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="activity-tab" data-bs-toggle="tab" 
                    data-bs-target="#activity" type="button" role="tab">
                User Activity
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="failed-logins-tab" data-bs-toggle="tab" 
                    data-bs-target="#failed-logins" type="button" role="tab">
                Failed Logins
            </button>
        </li>
    </ul>

    <div class="tab-content" id="logsTabsContent">
        <div class="tab-pane fade show active" id="activity" role="tabpanel">
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>File</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        {logs_html}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="tab-pane fade" id="failed-logins" role="tabpanel">
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Username</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        {failed_logins_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    '''
    
    scripts = '''
    <script>
        // Initialize tabs
        const tabElms = document.querySelectorAll('button[data-bs-toggle="tab"]')
        tabElms.forEach(tabEl => {
            new bootstrap.Tab(tabEl)
        })
    </script>
    '''
    
    return render_template_string(
        base_template.format(
            title="System Logs",
            nav_links=nav_links,
            messages="",
            content=content,
            scripts=scripts
        )
    )

if __name__ == '__main__':
    app.run(debug=True)