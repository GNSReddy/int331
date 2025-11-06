from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
import sqlite3
import logging
from datetime import datetime
import ipaddress

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['TEMP_FOLDER'] = 'temp'
app.config['DATABASE'] = 'file_system.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

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
    
    # Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE
    )
    ''')
    
    # Files table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        encrypted_filename TEXT NOT NULL,
        upload_date TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Activity logs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        filename TEXT,
        ip_address TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Failed login attempts
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS failed_logins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
    ''')
    
    # Add admin user if not exists
    admin_hash = generate_password_hash('admin123')
    cursor.execute('INSERT OR IGNORE INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)', 
                  ('admin', admin_hash, True))
    
    conn.commit()
    conn.close()

init_db()

# Logging setup
logging.basicConfig(filename='security.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

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
    
    # Check for suspicious IP (simplified example)
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            logging.warning(f"External IP access: {ip} for action: {action}")
    except ValueError:
        pass
    
    conn.execute('INSERT INTO file_logs (user_id, action, filename, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)',
                 (user_id, action, filename, ip, timestamp))
    conn.commit()
    conn.close()
    
    # Also log to security.log
    logging.info(f"User {user_id} performed {action} on {filename or 'system'} from IP {ip}")

def is_suspicious_ip(ip):
    """Basic check for suspicious IP patterns (simplified example)"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return True

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

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
        logging.info(f"New user registered: {username}")
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT id, username, password_hash, is_admin FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            user_obj = User(user['id'], user['username'], user['is_admin'])
            login_user(user_obj)
            
            log_activity(user['id'], 'login')
            logging.info(f"User logged in: {username}")
            
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Log failed login attempt
            ip = request.remote_addr
            timestamp = datetime.now().isoformat()
            
            conn = get_db_connection()
            conn.execute('INSERT INTO failed_logins (username, ip_address, timestamp) VALUES (?, ?, ?)',
                         (username, ip, timestamp))
            conn.commit()
            conn.close()
            
            logging.warning(f"Failed login attempt for username: {username} from IP: {ip}")
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'logout')
    logging.info(f"User logged out: {current_user.username}")
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    files = conn.execute('SELECT id, filename, upload_date, file_size FROM files WHERE user_id = ? ORDER BY upload_date DESC', 
                         (current_user.id,)).fetchall()
    conn.close()
    return render_template('dashboard.html', files=files)

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
            # Encrypt the file
            encrypted_data = cipher_suite.encrypt(file.read())
            
            # Generate unique filename
            original_filename = file.filename
            encrypted_filename = f"enc_{current_user.id}_{datetime.now().timestamp()}_{original_filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            
            # Save encrypted file
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Store file metadata in database
            file_size = len(encrypted_data)
            upload_date = datetime.now().isoformat()
            
            conn = get_db_connection()
            conn.execute('INSERT INTO files (user_id, filename, encrypted_filename, upload_date, file_size) VALUES (?, ?, ?, ?, ?)',
                         (current_user.id, original_filename, encrypted_filename, upload_date, file_size))
            conn.commit()
            conn.close()
            
            log_activity(current_user.id, 'upload', original_filename)
            logging.info(f"File uploaded: {original_filename} by user {current_user.username}")
            
            flash('File uploaded successfully', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    conn = get_db_connection()
    file_data = conn.execute('SELECT filename, encrypted_filename FROM files WHERE id = ? AND user_id = ?',
                            (file_id, current_user.id)).fetchone()
    conn.close()
    
    if not file_data:
        abort(404)
    
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data['encrypted_filename'])
    
    if not os.path.exists(encrypted_path):
        abort(404)
    
    # Read and decrypt the file
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    
    # Create temporary decrypted file
    temp_filename = f"temp_{file_data['filename']}"
    temp_path = os.path.join(app.config['TEMP_FOLDER'], temp_filename)
    
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    
    log_activity(current_user.id, 'download', file_data['filename'])
    logging.info(f"File downloaded: {file_data['filename']} by user {current_user.username}")
    
    # Send file and schedule cleanup (in a real app, use a proper task queue)
    response = send_file(temp_path, as_attachment=True, download_name=file_data['filename'])
    
    # Clean up the temp file after sending (in production, use proper async cleanup)
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
    file_data = conn.execute('SELECT filename, encrypted_filename FROM files WHERE id = ? AND user_id = ?',
                            (file_id, current_user.id)).fetchone()
    
    if not file_data:
        conn.close()
        abort(404)
    
    # Delete file record from database
    conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
    conn.commit()
    conn.close()
    
    # Delete the actual file
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data['encrypted_filename'])
    if os.path.exists(encrypted_path):
        os.unlink(encrypted_path)
    
    log_activity(current_user.id, 'delete', file_data['filename'])
    logging.info(f"File deleted: {file_data['filename']} by user {current_user.username}")
    
    flash('File deleted successfully', 'success')
    return redirect(url_for('dashboard'))

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
    
    failed_logins = conn.execute('SELECT * FROM failed_logins ORDER BY timestamp DESC LIMIT 50').fetchall()
    conn.close()
    
    log_activity(current_user.id, 'view_logs')
    logging.info(f"Admin {current_user.username} viewed system logs")
    
    return render_template('logs.html', logs=logs, failed_logins=failed_logins)

if __name__ == '__main__':
    app.run(debug=True)