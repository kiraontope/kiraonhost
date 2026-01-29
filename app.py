# real code make by @blackparahexleak
# code full translate by @nr_codex
# premium features added: folder management, archive extraction

import os
import json
import re
import subprocess
import psutil
import socket
import sys
import hashlib
import secrets
import time
import zipfile
import tarfile
import io
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, send_from_directory, request, jsonify, session, redirect, url_for, make_response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, "USERS")
os.makedirs(USERS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload

running_procs = {}
USERS_FILE = os.path.join(BASE_DIR, "users.json")
REMEMBER_TOKENS_FILE = os.path.join(BASE_DIR, "remember_tokens.json")

# Main account (Admin)
ADMIN_USERNAME = "kira"
ADMIN_PASSWORD = "1"

# ============== Helper Functions ==============

def init_users_db():
    """Initialize users database"""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            # Create main account automatically
            admin_data = {
                ADMIN_USERNAME: {
                    "password": hash_password(ADMIN_PASSWORD),
                    "created_at": datetime.now().isoformat(),
                    "last_login": None,
                    "theme": "premium",
                    "is_admin": True,
                    "can_create_users": True
                }
            }
            json.dump(admin_data, f, indent=2)

def init_tokens_db():
    """Initialize remember tokens database"""
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)

def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_remember_token(username):
    """Create new remember token for user"""
    init_tokens_db()
    
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    
    tokens[token] = {
        "username": username,
        "created_at": datetime.now().isoformat(),
        "expires_at": expires,
        "last_used": datetime.now().isoformat()
    }
    
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    
    return token

def validate_remember_token(token):
    """Validate remember token"""
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        return None
    
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    
    if token not in tokens:
        return None
    
    token_data = tokens[token]
    expires_at = datetime.fromisoformat(token_data["expires_at"])
    
    if datetime.now() > expires_at:
        del tokens[token]
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)
        return None
    
    token_data["last_used"] = datetime.now().isoformat()
    tokens[token] = token_data
    
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    
    return token_data["username"]

def delete_remember_token(token):
    """Delete remember token"""
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        return
    
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    
    if token in tokens:
        del tokens[token]
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)

def delete_all_user_tokens(username):
    """Delete all remember tokens for user"""
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        return
    
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    
    tokens_to_delete = []
    for token, data in tokens.items():
        if data["username"] == username:
            tokens_to_delete.append(token)
    
    for token in tokens_to_delete:
        del tokens[token]
    
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)

def register_user(username, password, created_by_admin=False):
    """Register a new user"""
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username in users:
        return False, "User already exists"
    
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    
    # Check username validity
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers and underscores"
    
    users[username] = {
        "password": hash_password(password),
        "created_at": datetime.now().isoformat(),
        "last_login": None,
        "theme": "premium",
        "is_admin": username == ADMIN_USERNAME,
        "created_by_admin": created_by_admin,
        "created_by": session.get('username') if 'username' in session else None
    }
    
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    # Create user directory
    user_dir = os.path.join(USERS_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    
    # Create SERVERS directory for the user
    servers_dir = os.path.join(user_dir, "SERVERS")
    os.makedirs(servers_dir, exist_ok=True)
    
    return True, "Account created successfully"

def authenticate_user(username, password):
    """Authenticate user"""
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username not in users:
        return False, "User not found"
    
    if users[username]["password"] != hash_password(password):
        return False, "Incorrect password"
    
    # Update last login
    users[username]["last_login"] = datetime.now().isoformat()
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    return True, "Login successful"

def is_admin(username):
    """Check if user is admin"""
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username in users:
        return users[username].get("is_admin", False)
    return False

def get_user_servers_dir(username):
    """Get user's servers directory"""
    return os.path.join(USERS_DIR, username, "SERVERS")

def ensure_user_servers_dir():
    """Ensure user's servers directory exists"""
    if 'username' not in session:
        return None
    
    user_dir = get_user_servers_dir(session['username'])
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def sanitize_folder_name(name):
    """Sanitize folder name"""
    if not name: 
        return ""
    name = name.strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-\_\.]", "", name)
    return name[:200]

def sanitize_filename(name):
    """Sanitize filename"""
    if not name: 
        return ""
    name = name.strip()
    name = re.sub(r"[^\w\s\.\-]", "", name)
    name = re.sub(r"\s+", "-", name)
    return name[:200]

def ensure_meta(folder):
    """Ensure meta.json exists for a folder"""
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return None
    
    meta_path = os.path.join(user_servers_dir, folder, "meta.json")
    if not os.path.exists(meta_path):
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"display_name": folder, "startup_file": ""}, f)
    return meta_path

def get_ip():
    """Get server IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: 
        return '127.0.0.1'

def load_servers_list():
    """Load list of servers for current user"""
    if 'username' not in session:
        return []
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir or not os.path.exists(user_servers_dir):
        return []
    
    try:
        entries = [d for d in os.listdir(user_servers_dir) 
                  if os.path.isdir(os.path.join(user_servers_dir, d))]
    except: 
        entries = []
    
    servers = []
    for i, folder in enumerate(entries, start=1):
        ensure_meta(folder)
        meta_path = os.path.join(user_servers_dir, folder, "meta.json")
        display_name, startup_file = folder, ""
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                display_name = meta.get("display_name", folder)
                startup_file = meta.get("startup_file", "")
        except: 
            pass
        
        # Get server status
        proc_key = f"{session['username']}_{folder}"
        is_running = proc_key in running_procs and running_procs[proc_key].poll() is None
        
        servers.append({
            "id": i, 
            "title": display_name, 
            "folder": folder, 
            "subtitle": f"Node-{i} Â· Local", 
            "startup_file": startup_file,
            "status": "Running" if is_running else "Offline"
        })
    return servers

def is_archive_file(filename):
    """Check if file is an archive"""
    archive_extensions = ['.zip', '.tar', '.tar.gz', '.tgz', '.rar', '.7z']
    return any(filename.lower().endswith(ext) for ext in archive_extensions)

def get_file_type(filename):
    """Get file type based on extension"""
    if not filename:
        return "Unknown"
    
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    
    file_types = {
        'py': 'Python',
        'js': 'JavaScript',
        'html': 'HTML',
        'htm': 'HTML',
        'css': 'CSS',
        'json': 'JSON',
        'txt': 'Text',
        'md': 'Markdown',
        'log': 'Log',
        'zip': 'ZIP Archive',
        'rar': 'RAR Archive',
        '7z': '7-Zip Archive',
        'tar': 'TAR Archive',
        'gz': 'GZIP Archive',
        'tgz': 'GZIP Archive',
        'jpg': 'Image',
        'jpeg': 'Image',
        'png': 'Image',
        'gif': 'Image',
        'svg': 'Image',
        'pdf': 'PDF Document',
        'exe': 'Executable',
        'sh': 'Shell Script',
        'bat': 'Batch File',
        'ps1': 'PowerShell',
        'sql': 'SQL',
        'xml': 'XML',
        'yml': 'YAML',
        'yaml': 'YAML',
        'csv': 'CSV',
        'ini': 'Config',
        'cfg': 'Config',
        'conf': 'Config'
    }
    
    return file_types.get(ext, 'File')

def get_directory_size(path):
    """Calculate directory size"""
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.exists(fp):
                total_size += os.path.getsize(fp)
    return total_size

def format_file_size(size_in_bytes):
    """Format file size to human readable format"""
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    elif size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"

# ============== Routes ==============

@app.before_request
def check_remember_token():
    """Check remember token before each request"""
    if 'username' in session:
        return
    
    remember_token = request.cookies.get('remember_token')
    if remember_token:
        username = validate_remember_token(remember_token)
        if username:
            session['username'] = username
            session.permanent = True

@app.route("/")
def home():
    """Home route - redirects based on user type"""
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    # If user is admin, redirect to account creation panel
    if is_admin(session['username']):
        return send_from_directory(BASE_DIR, "admin_panel.html")
    
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/index.html")
def serve_index():
    """Serve main index page"""
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    if is_admin(session['username']):
        return redirect(url_for('home'))
    
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/login")
def login_page():
    """Login page"""
    if 'username' in session:
        return redirect(url_for('home'))
    return send_from_directory(BASE_DIR, "login.html")

@app.route("/admin")
def admin_panel():
    """Admin panel"""
    if 'username' not in session or not is_admin(session['username']):
        return redirect(url_for('login_page'))
    return send_from_directory(BASE_DIR, "admin_panel.html")

# ============== Authentication Routes ==============

@app.route("/api/register", methods=["POST"])
def api_register():
    """Register new user (admin only)"""
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"})
    
    success, message = register_user(username, password, created_by_admin=True)
    return jsonify({"success": success, "message": message})

@app.route("/api/login", methods=["POST"])
def api_login():
    """Login user"""
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    remember_me = data.get("remember_me", False)
    
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"})
    
    success, message = authenticate_user(username, password)
    if success:
        session['username'] = username
        
        response_data = {
            "success": True, 
            "message": message,
            "username": username,
            "is_admin": is_admin(username)
        }
        
        if remember_me:
            token = create_remember_token(username)
            response = make_response(jsonify(response_data))
            response.set_cookie(
                'remember_token',
                token,
                max_age=30*24*60*60,
                httponly=True,
                secure=False,
                samesite='Strict'
            )
            return response
        
        return jsonify(response_data)
    
    return jsonify({"success": False, "message": message})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Logout user"""
    username = session.get('username')
    
    if username:
        delete_all_user_tokens(username)
    
    session.pop('username', None)
    
    response = make_response(jsonify({"success": True, "message": "Logged out successfully"}))
    response.set_cookie('remember_token', '', expires=0)
    
    return response

@app.route("/api/current_user")
def api_current_user():
    """Get current user info"""
    if 'username' in session:
        admin = is_admin(session['username'])
        return jsonify({
            "success": True, 
            "username": session['username'],
            "is_admin": admin,
            "has_remember_token": bool(request.cookies.get('remember_token'))
        })
    return jsonify({"success": False})

@app.route("/api/user/settings", methods=["GET", "POST"])
def user_settings():
    """Get or update user settings"""
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    if request.method == "GET":
        init_users_db()
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)
        
        user_data = users.get(session['username'], {})
        return jsonify({
            "success": True,
            "username": session['username'],
            "created_at": user_data.get("created_at"),
            "last_login": user_data.get("last_login"),
            "theme": user_data.get("theme", "premium"),
            "is_admin": user_data.get("is_admin", False)
        })
    
    data = request.get_json()
    theme = data.get("theme", "premium")
    
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if session['username'] in users:
        users[session['username']]["theme"] = theme
        
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        
        return jsonify({"success": True, "message": "Settings updated"})
    
    return jsonify({"success": False, "message": "User not found"})

# ============== Server Management Routes ==============

@app.route("/servers")
def get_servers():
    """Get list of servers for current user"""
    if 'username' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    return jsonify({"success": True, "servers": load_servers_list()})

@app.route("/add", methods=["POST"])
def add_server():
    """Add new server"""
    if 'username' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    
    if not name:
        return jsonify({"success": False, "message": "Server name is required"}), 400
    
    folder = sanitize_folder_name(name)
    
    if not folder:
        return jsonify({"success": False, "message": "Invalid server name"}), 400
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False, "message": "Server directory not found"}), 404
    
    target = os.path.join(user_servers_dir, folder)
    
    if os.path.exists(target): 
        return jsonify({"success": False, "message": "Server already exists"}), 409
    
    try:
        os.makedirs(target)
        ensure_meta(folder)
        
        # Create default files
        open(os.path.join(target, "server.log"), "w").close()
        
        # Create a sample Python file
        sample_py = os.path.join(target, "main.py")
        with open(sample_py, "w", encoding="utf-8") as f:
            f.write('''# Sample Python Server
from flask import Flask, jsonify
import time

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({
        "status": "running",
        "message": "Hello from your Python server!",
        "timestamp": time.time()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
''')
        
        return jsonify({"success": True, "servers": load_servers_list(), "message": "Server created successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error creating server: {str(e)}"}), 500

@app.route("/server/stats/<folder>")
def get_stats(folder):
    """Get server statistics"""
    if 'username' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    proc_key = f"{session['username']}_{folder}"
    proc = running_procs.get(proc_key)
    running = False
    cpu = "0%"
    mem = "0 MB"
    
    if proc and proc.poll() is None:
        try:
            p = psutil.Process(proc.pid)
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                running = True
                cpu = f"{p.cpu_percent(interval=0.1):.1f}%"
                mem_mb = p.memory_info().rss / 1024 / 1024
                mem = f"{mem_mb:.1f} MB"
        except: 
            pass
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False, "message": "Server directory not found"}), 404
    
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    logs = ""
    
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                logs = f.read()
        except:
            logs = "Error reading logs"
    
    # Get startup file
    startup_file = ""
    meta_path = os.path.join(user_servers_dir, folder, "meta.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                startup_file = meta.get("startup_file", "")
        except:
            pass
    
    return jsonify({
        "success": True,
        "status": "Running" if running else "Offline", 
        "cpu": cpu, 
        "mem": mem, 
        "logs": logs, 
        "ip": get_ip(),
        "startup_file": startup_file
    })

@app.route("/server/action/<folder>/<act>", methods=["POST"])
def server_action(folder, act):
    """Perform server action (start/stop/restart)"""
    if 'username' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    proc_key = f"{session['username']}_{folder}"
    
    # Stop server if running
    if proc_key in running_procs:
        try:
            if running_procs[proc_key].poll() is None:
                p = psutil.Process(running_procs[proc_key].pid)
                for child in p.children(recursive=True): 
                    try:
                        child.kill()
                    except:
                        pass
                try:
                    p.kill()
                except:
                    pass
        except: 
            pass
        
        del running_procs[proc_key]
    
    if act == "stop": 
        return jsonify({"success": True, "message": "Server stopped"})

    # Start or restart server
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False, "message": "Server directory not found"}), 404
    
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    
    try:
        open(log_path, "w").close()
    except:
        pass
    
    meta_path = ensure_meta(folder)
    if not meta_path:
        return jsonify({"success": False, "message": "Server folder not found"}), 404
    
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            startup = json.load(f).get("startup_file")
    except:
        startup = ""
    
    if not startup: 
        return jsonify({"success": False, "message": "No startup file set. Please set a main file first."}), 400
    
    startup_path = os.path.join(user_servers_dir, folder, startup)
    if not os.path.exists(startup_path):
        return jsonify({"success": False, "message": f"Startup file '{startup}' not found"}), 404
    
    try:
        log_file = open(log_path, "a")
        proc = subprocess.Popen(
            [sys.executable, "-u", startup], 
            cwd=os.path.join(user_servers_dir, folder), 
            stdout=log_file, 
            stderr=log_file,
            bufsize=1,
            universal_newlines=True
        )
        running_procs[proc_key] = proc
        
        # Write startup message to log
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\n[INFO] Server started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"[INFO] Startup file: {startup}\n")
            f.write(f"[INFO] Process ID: {proc.pid}\n")
            f.write("="*50 + "\n")
        
        return jsonify({"success": True, "message": "Server started successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error starting server: {str(e)}"}), 500

# ============== File Management Routes ==============

@app.route("/files/list/<folder>")
def list_files(folder):
    """List files in server folder"""
    if 'username' not in session:
        return jsonify([]), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify([]), 404
    
    base_path = os.path.join(user_servers_dir, folder)
    
    if not os.path.exists(base_path):
        return jsonify([])
    
    files = []
    try:
        for item in os.listdir(base_path):
            item_path = os.path.join(base_path, item)
            
            # Skip system files and directories
            if item in ["meta.json", "server.log", "__pycache__"]:
                continue
            
            if os.path.isfile(item_path):
                size = os.path.getsize(item_path)
                file_type = get_file_type(item)
                
                files.append({
                    "name": item,
                    "size": format_file_size(size),
                    "type": file_type,
                    "is_archive": is_archive_file(item),
                    "modified": os.path.getmtime(item_path)
                })
    except Exception as e:
        print(f"Error listing files: {e}")
    
    # Sort files by name
    files.sort(key=lambda x: x["name"].lower())
    
    return jsonify(files)

@app.route("/files/folders/<folder>")
def list_folders(folder):
    """List folders in server directory"""
    if 'username' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False, "message": "Server directory not found"}), 404
    
    base_path = os.path.join(user_servers_dir, folder)
    
    if not os.path.exists(base_path):
        return jsonify({"success": True, "folders": []})
    
    folders = []
    try:
        for item in os.listdir(base_path):
            item_path = os.path.join(base_path, item)
            
            # Skip files and system directories
            if not os.path.isdir(item_path) or item in ["__pycache__"]:
                continue
            
            try:
                items = os.listdir(item_path)
                file_count = len([f for f in items if os.path.isfile(os.path.join(item_path, f))])
                folder_count = len([d for d in items if os.path.isdir(os.path.join(item_path, d))])
                
                # Calculate folder size
                folder_size = get_directory_size(item_path)
                
                folders.append({
                    "name": item,
                    "file_count": file_count,
                    "folder_count": folder_count,
                    "size": format_file_size(folder_size),
                    "created": os.path.getctime(item_path),
                    "modified": os.path.getmtime(item_path)
                })
            except:
                # If we can't read the folder, still include it
                folders.append({
                    "name": item,
                    "file_count": 0,
                    "folder_count": 0,
                    "size": "0 B",
                    "created": 0,
                    "modified": 0
                })
    except Exception as e:
        print(f"Error listing folders: {e}")
    
    # Sort folders by name
    folders.sort(key=lambda x: x["name"].lower())
    
    return jsonify({"success": True, "folders": folders})

@app.route("/files/create-folder/<folder>", methods=["POST"])
def create_folder(folder):
    """Create a new folder"""
    if 'username' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False, "message": "Server directory not found"}), 404
    
    data = request.get_json()
    folder_name = data.get('folder_name', '').strip()
    path = data.get('path', '').strip()
    
    if not folder_name:
        return jsonify({"success": False, "message": "Folder name is required"})
    
    # Sanitize folder name
    folder_name = sanitize_folder_name(folder_name)
    if not folder_name:
        return jsonify({"success": False, "message": "Invalid folder name"})
    
    # Build full path
    if path:
        target_dir = os.path.join(user_servers_dir, folder, path)
        target_path = os.path.join(target_dir, folder_name)
    else:
        target_dir = os.path.join(user_servers_dir, folder)
        target_path = os.path.join(target_dir, folder_name)
    
    # Ensure parent directory exists
    try:
        os.makedirs(target_dir, exist_ok=True)
    except Exception as e:
        return jsonify({"success": False, "message": f"Cannot create directory: {str(e)}"})
    
    # Check if folder already exists
    if os.path.exists(target_path):
        return jsonify({"success": False, "message": "Folder already exists"})
    
    # Create folder
    try:
        os.makedirs(target_path, exist_ok=True)
        return jsonify({
            "success": True,
            "message": f"Folder '{folder_name}' created successfully",
            "folder_name": folder_name
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Error creating folder: {str(e)}"})

@app.route("/files/content/<folder>/<filename>")
def get_file_content(folder, filename):
    """Get file content"""
    if 'username' not in session:
        return jsonify({"content": ""}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"content": ""}), 404
    
    file_path = os.path.join(user_servers_dir, folder, filename)
    
    # Security check
    if not file_path.startswith(user_servers_dir):
        return jsonify({"content": ""}), 403
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return jsonify({"content": f.read()})
    except UnicodeDecodeError:
        # Try binary read for non-text files
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                return jsonify({"content": "[Binary file - cannot display]"})
        except:
            return jsonify({"content": ""})
    except: 
        return jsonify({"content": ""})

@app.route("/files/save/<folder>/<filename>", methods=["POST"])
def save_file_content(folder, filename):
    """Save file content"""
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False}), 404
    
    file_path = os.path.join(user_servers_dir, folder, filename)
    
    # Security check
    if not file_path.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
    
    data = request.json
    content = data.get('content', '')
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return jsonify({"success": True, "message": "File saved successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error saving file: {str(e)}"})

@app.route("/files/upload/<folder>", methods=["POST"])
def upload_file(folder):
    """Upload files to server"""
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False}), 404
    
    auto_extract = request.form.get('auto_extract', 'false').lower() == 'true'
    
    # Check for folder zip upload
    if 'folder_zip' in request.files:
        return upload_folder_zip(folder)
    
    # Upload multiple files
    uploaded_files = request.files.getlist('files[]')
    results = []
    uploaded_count = 0
    
    for f in uploaded_files:
        if f and f.filename:
            safe_name = sanitize_filename(f.filename)
            if not safe_name:
                continue
                
            save_path = os.path.join(user_servers_dir, folder, safe_name)
            
            try:
                f.save(save_path)
                file_size = os.path.getsize(save_path)
                uploaded_count += 1
                
                # Check if it's an archive and auto-extract is enabled
                extracted = False
                extracted_count = 0
                
                if auto_extract and is_archive_file(safe_name):
                    try:
                        extract_path = os.path.join(user_servers_dir, folder)
                        
                        if safe_name.endswith('.zip'):
                            with zipfile.ZipFile(save_path, 'r') as zip_ref:
                                file_list = zip_ref.namelist()
                                extracted_count = len(file_list)
                                zip_ref.extractall(extract_path)
                                extracted = True
                                
                        elif safe_name.endswith('.tar.gz') or safe_name.endswith('.tgz'):
                            with tarfile.open(save_path, 'r:gz') as tar_ref:
                                file_list = tar_ref.getnames()
                                extracted_count = len(file_list)
                                tar_ref.extractall(extract_path)
                                extracted = True
                                
                        elif safe_name.endswith('.tar'):
                            with tarfile.open(save_path, 'r:') as tar_ref:
                                file_list = tar_ref.getnames()
                                extracted_count = len(file_list)
                                tar_ref.extractall(extract_path)
                                extracted = True
                        
                        # Remove the archive after extraction if auto-extract is enabled
                        if extracted:
                            os.remove(save_path)
                            
                    except Exception as e:
                        print(f"Error extracting archive {safe_name}: {e}")
                        extracted = False
                
                results.append({
                    "name": safe_name,
                    "size": format_file_size(file_size),
                    "extracted": extracted,
                    "extracted_count": extracted_count if extracted else 0
                })
                
            except Exception as e:
                results.append({
                    "name": safe_name,
                    "size": "0 B",
                    "extracted": False,
                    "error": str(e)
                })
    
    return jsonify({
        "success": True, 
        "message": f"Successfully uploaded {uploaded_count} file(s)",
        "uploaded_files": results
    })

def upload_folder_zip(folder):
    """Handle folder upload as zip"""
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False}), 404
    
    zip_file = request.files['folder_zip']
    
    if zip_file and zip_file.filename:
        try:
            # Read zip file
            zip_data = io.BytesIO(zip_file.read())
            
            with zipfile.ZipFile(zip_data, 'r') as zip_ref:
                # Get list of files
                file_list = zip_ref.namelist()
                
                # Extract all files
                extract_path = os.path.join(user_servers_dir, folder)
                zip_ref.extractall(extract_path)
                
                # Count extracted items
                extracted_folders = set()
                extracted_files = []
                
                for file_path in file_list:
                    full_path = os.path.join(extract_path, file_path)
                    if os.path.isfile(full_path):
                        extracted_files.append({
                            "name": os.path.basename(file_path),
                            "path": file_path,
                            "size": format_file_size(os.path.getsize(full_path))
                        })
                    elif os.path.isdir(full_path):
                        extracted_folders.add(os.path.dirname(file_path))
                
            return jsonify({
                "success": True,
                "message": f"Folder uploaded and extracted successfully",
                "extracted_files": extracted_files,
                "extracted_folders": list(extracted_folders),
                "total_files": len(extracted_files),
                "total_folders": len(extracted_folders)
            })
            
        except zipfile.BadZipFile:
            return jsonify({"success": False, "message": "Invalid zip file"})
        except Exception as e:
            return jsonify({"success": False, "message": f"Error extracting zip: {str(e)}"})
    
    return jsonify({"success": False, "message": "Please upload a valid zip file"})

@app.route("/files/extract/<folder>/<filename>", methods=["POST"])
def extract_archive(folder, filename):
    """Extract archive file"""
    if 'username' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False, "message": "Server directory not found"}), 404
    
    file_path = os.path.join(user_servers_dir, folder, filename)
    
    if not os.path.exists(file_path):
        return jsonify({"success": False, "message": "File not found"})
    
    if not is_archive_file(filename):
        return jsonify({"success": False, "message": "Not a supported archive file"})
    
    try:
        extract_path = os.path.join(user_servers_dir, folder)
        
        if filename.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Get list of extracted files
                file_list = zip_ref.namelist()
                zip_ref.extractall(extract_path)
                
                # Count extracted items
                extracted_files = []
                extracted_folders = set()
                
                for extracted_file in file_list:
                    full_path = os.path.join(extract_path, extracted_file)
                    if os.path.isfile(full_path):
                        extracted_files.append({
                            "name": os.path.basename(extracted_file),
                            "path": extracted_file,
                            "size": format_file_size(os.path.getsize(full_path))
                        })
                    elif os.path.isdir(full_path):
                        extracted_folders.add(os.path.dirname(extracted_file))
        
        elif filename.endswith('.tar.gz') or filename.endswith('.tgz'):
            with tarfile.open(file_path, 'r:gz') as tar_ref:
                file_list = tar_ref.getnames()
                tar_ref.extractall(extract_path)
                
                extracted_files = []
                extracted_folders = set()
                
                for extracted_file in file_list:
                    full_path = os.path.join(extract_path, extracted_file)
                    if os.path.isfile(full_path):
                        extracted_files.append({
                            "name": os.path.basename(extracted_file),
                            "path": extracted_file,
                            "size": format_file_size(os.path.getsize(full_path))
                        })
                    elif os.path.isdir(full_path):
                        extracted_folders.add(os.path.dirname(extracted_file))
        
        elif filename.endswith('.tar'):
            with tarfile.open(file_path, 'r:') as tar_ref:
                file_list = tar_ref.getnames()
                tar_ref.extractall(extract_path)
                
                extracted_files = []
                extracted_folders = set()
                
                for extracted_file in file_list:
                    full_path = os.path.join(extract_path, extracted_file)
                    if os.path.isfile(full_path):
                        extracted_files.append({
                            "name": os.path.basename(extracted_file),
                            "path": extracted_file,
                            "size": format_file_size(os.path.getsize(full_path))
                        })
                    elif os.path.isdir(full_path):
                        extracted_folders.add(os.path.dirname(extracted_file))
        
        else:
            return jsonify({"success": False, "message": "Unsupported archive format"})
        
        # Delete the archive after extraction
        try:
            os.remove(file_path)
        except:
            pass
        
        return jsonify({
            "success": True,
            "message": "Archive extracted successfully",
            "extracted_files": extracted_files,
            "extracted_folders": list(extracted_folders),
            "total_files": len(extracted_files),
            "total_folders": len(extracted_folders)
        })
        
    except Exception as e:
        return jsonify({"success": False, "message": f"Error extracting archive: {str(e)}"})

@app.route("/files/rename/<folder>", methods=["POST"])
def rename_file(folder):
    """Rename file"""
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False}), 404
    
    data = request.get_json()
    old_name = data.get('old', '').strip()
    new_name = data.get('new', '').strip()
    
    if not old_name or not new_name:
        return jsonify({"success": False, "message": "Both old and new names are required"})
    
    # Sanitize new name
    new_name = sanitize_filename(new_name)
    if not new_name:
        return jsonify({"success": False, "message": "Invalid new filename"})
    
    old_path = os.path.join(user_servers_dir, folder, old_name)
    new_path = os.path.join(user_servers_dir, folder, new_name)
    
    # Security check
    if not old_path.startswith(user_servers_dir) or not new_path.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
    
    if not os.path.exists(old_path):
        return jsonify({"success": False, "message": "File not found"})
    
    if os.path.exists(new_path):
        return jsonify({"success": False, "message": "File with new name already exists"})
    
    try:
        os.rename(old_path, new_path)
        return jsonify({"success": True, "message": "File renamed successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error renaming file: {str(e)}"})

@app.route("/files/delete/<folder>", methods=["POST"])
def delete_file(folder):
    """Delete file"""
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False}), 404
    
    data = request.get_json()
    filename = data.get('name', '').strip()
    
    if not filename:
        return jsonify({"success": False, "message": "Filename is required"})
    
    file_path = os.path.join(user_servers_dir, folder, filename)
    
    # Security check
    if not file_path.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
    
    if not os.path.exists(file_path):
        return jsonify({"success": False, "message": "File not found"})
    
    try:
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)
        else:
            os.remove(file_path)
        return jsonify({"success": True, "message": "File deleted successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error deleting file: {str(e)}"})

# FIXED: Download file endpoint
@app.route("/files/download/<folder>/<filename>")
def download_file(folder, filename):
    """Download file"""
    if 'username' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False, "message": "Server directory not found"}), 404
    
    file_path = os.path.join(user_servers_dir, folder, filename)
    
    # Security check
    if not file_path.startswith(user_servers_dir):
        return jsonify({"success": False, "message": "Access denied"}), 403
    
    if not os.path.exists(file_path):
        return jsonify({"success": False, "message": "File not found"}), 404
    
    try:
        # Check if file is readable
        if not os.access(file_path, os.R_OK):
            return jsonify({"success": False, "message": "Cannot read file"}), 403
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # For text files, we can send as response
        if filename.endswith(('.txt', '.py', '.js', '.html', '.css', '.json', '.md', '.log')):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                response = make_response(content)
                response.headers['Content-Type'] = 'text/plain'
                response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
                return response
            except:
                # If text reading fails, send as binary
                pass
        
        # For binary files, use Flask's send_file
        try:
            from flask import send_file
            return send_file(
                file_path,
                as_attachment=True,
                download_name=filename,
                mimetype='application/octet-stream'
            )
        except ImportError:
            # Fallback method if send_file is not available
            with open(file_path, 'rb') as f:
                content = f.read()
            response = make_response(content)
            response.headers['Content-Type'] = 'application/octet-stream'
            response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
            response.headers['Content-Length'] = str(file_size)
            return response
            
    except Exception as e:
        print(f"Error downloading file {filename}: {e}")
        return jsonify({"success": False, "message": f"Error downloading file: {str(e)}"}), 500

@app.route("/files/install/<folder>", methods=["POST"])
def install_req(folder):
    """Install libraries from requirements.txt file"""
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return jsonify({"success": False}), 404
    
    # Check if requirements.txt exists
    req_path = os.path.join(user_servers_dir, folder, "requirements.txt")
    if not os.path.exists(req_path):
        return jsonify({"success": False, "message": "requirements.txt file not found"})
    
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    
    # Write start message to log
    try:
        with open(log_path, "w", encoding="utf-8") as log_file:
            log_file.write(f"[SYSTEM] Starting Installation at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_file.write(f"[SYSTEM] Installing packages from: {req_path}\n")
            log_file.write(f"[SYSTEM] Python executable: {sys.executable}\n")
            log_file.write(f"[SYSTEM] Working directory: {os.path.join(user_servers_dir, folder)}\n")
            log_file.write("="*50 + "\n")
    except:
        pass
    
    # Run installation process
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
            cwd=os.path.join(user_servers_dir, folder), 
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Read output and add to log
        output_lines = []
        with open(log_path, "a", encoding="utf-8") as log_file:
            for line in proc.stdout:
                log_file.write(line)
                log_file.flush()
                output_lines.append(line)
        
        proc.wait()
        
        # Write installation result
        with open(log_path, "a", encoding="utf-8") as log_file:
            log_file.write("\n" + "="*50 + "\n")
            if proc.returncode == 0:
                log_file.write("[SYSTEM] Installation completed successfully!\n")
            else:
                log_file.write(f"[SYSTEM] Installation failed with exit code: {proc.returncode}\n")
        
        return jsonify({"success": True, "message": "Installation started"})
    
    except Exception as e:
        try:
            with open(log_path, "a", encoding="utf-8") as log_file:
                log_file.write(f"\n[ERROR] Failed to start installation: {str(e)}\n")
        except:
            pass
        
        return jsonify({"success": False, "message": f"Failed to start installation: {str(e)}"})

@app.route("/server/set-startup/<folder>", methods=["POST"])
def set_startup(folder):
    """Set startup file for server"""
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    meta_path = ensure_meta(folder)
    if not meta_path:
        return jsonify({"success": False}), 404
    
    data = request.get_json()
    startup_file = data.get('file', '').strip()
    
    if not startup_file:
        return jsonify({"success": False, "message": "Startup file is required"})
    
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        
        meta["startup_file"] = startup_file
        
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f)
        
        return jsonify({"success": True, "message": "Startup file set successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error setting startup file: {str(e)}"})

# ============== Admin Routes ==============

@app.route("/api/admin/users", methods=["GET"])
def get_all_users():
    """Get list of all users (admin only)"""
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    user_list = []
    for username, data in users.items():
        if username != ADMIN_USERNAME:  # Don't show admin themselves
            user_list.append({
                "username": username,
                "created_at": data.get("created_at"),
                "last_login": data.get("last_login"),
                "created_by": data.get("created_by", "system"),
                "theme": data.get("theme", "premium")
            })
    
    return jsonify({"success": True, "users": user_list})

@app.route("/api/admin/delete-user", methods=["POST"])
def delete_user():
    """Delete user (admin only)"""
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    data = request.get_json()
    username_to_delete = data.get("username", "").strip()
    
    if not username_to_delete or username_to_delete == ADMIN_USERNAME:
        return jsonify({"success": False, "message": "Cannot delete this user"})
    
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username_to_delete not in users:
        return jsonify({"success": False, "message": "User not found"})
    
    # Delete user
    del users[username_to_delete]
    
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    # Delete user directory if exists
    user_dir = os.path.join(USERS_DIR, username_to_delete)
    if os.path.exists(user_dir):
        try:
            shutil.rmtree(user_dir)
        except:
            pass
    
    # Delete user's remember tokens
    try:
        with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
            tokens = json.load(f)
        
        tokens_to_delete = []
        for token, data in tokens.items():
            if data["username"] == username_to_delete:
                tokens_to_delete.append(token)
        
        for token in tokens_to_delete:
            del tokens[token]
        
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)
    except:
        pass
    
    return jsonify({"success": True, "message": "User deleted successfully"})

@app.route("/api/admin/stats")
def get_admin_stats():
    """Get admin statistics"""
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    try:
        # Get user count
        init_users_db()
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)
        
        user_count = len(users)
        
        # Get total servers count
        total_servers = 0
        for username in users.keys():
            user_servers_dir = os.path.join(USERS_DIR, username, "SERVERS")
            if os.path.exists(user_servers_dir):
                try:
                    servers = [d for d in os.listdir(user_servers_dir) 
                              if os.path.isdir(os.path.join(user_servers_dir, d))]
                    total_servers += len(servers)
                except:
                    pass
        
        # Get system info
        system_info = {
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
            "cpu_count": psutil.cpu_count(),
            "total_memory": format_file_size(psutil.virtual_memory().total),
            "disk_usage": psutil.disk_usage('/').percent
        }
        
        return jsonify({
            "success": True,
            "stats": {
                "total_users": user_count,
                "total_servers": total_servers,
                "running_servers": len(running_procs),
                "system_info": system_info
            }
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# ============== Utility Routes ==============

@app.route("/api/system/info")
def get_system_info():
    """Get system information"""
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    try:
        info = {
            "ip_address": get_ip(),
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
            "cpu_count": psutil.cpu_count(),
            "memory_total": format_file_size(psutil.virtual_memory().total),
            "memory_used": format_file_size(psutil.virtual_memory().used),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "uptime": time.time() - psutil.boot_time()
        }
        
        return jsonify({"success": True, "info": info})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/server/restart-all", methods=["POST"])
def restart_all_servers():
    """Restart all running servers"""
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    try:
        restarted = 0
        for proc_key, proc in list(running_procs.items()):
            try:
                # Extract username and folder from proc_key
                if '_' in proc_key:
                    username, folder = proc_key.split('_', 1)
                    
                    # Stop the process
                    if proc.poll() is None:
                        try:
                            p = psutil.Process(proc.pid)
                            for child in p.children(recursive=True):
                                try:
                                    child.kill()
                                except:
                                    pass
                            try:
                                p.kill()
                            except:
                                pass
                        except:
                            pass
                    
                    del running_procs[proc_key]
                    restarted += 1
                    
                    # Log the restart
                    log_path = os.path.join(USERS_DIR, username, "SERVERS", folder, "server.log")
                    if os.path.exists(log_path):
                        with open(log_path, "a", encoding="utf-8") as f:
                            f.write(f"\n[SYSTEM] Server restarted by admin at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            except:
                continue
        
        return jsonify({"success": True, "message": f"Restarted {restarted} server(s)"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# ============== Error Handlers ==============

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return jsonify({"success": False, "message": "Page not found"}), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors"""
    return jsonify({"success": False, "message": "Internal server error"}), 500

@app.errorhandler(413)
def request_entity_too_large(e):
    """Handle file too large errors"""
    return jsonify({"success": False, "message": "File too large. Maximum size is 100MB"}), 413

# ============== Main Application ==============

if __name__ == "__main__":
    # Initialize databases
    init_users_db()
    init_tokens_db()
    
    # Create necessary directories
    os.makedirs(USERS_DIR, exist_ok=True)
    
    port = int(os.environ.get("SERVER_PORT", 21910))
    print(f"Starting HAMA HOST PANEL on http://{get_ip()}:{port}")
    print(f"Admin username: {ADMIN_USERNAME}")
    print(f"Admin password: {ADMIN_PASSWORD}")
    
    app.run(host="0.0.0.0", port=21910, debug=True)
    
# real code make by @blackparahexleak
# code full translate by @nr_codex
# premium features added: folder management, archive extraction
