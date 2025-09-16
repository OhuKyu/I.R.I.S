from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response, send_file
from iris import IRIS
from cache_manager import CacheManager
import json
import os
import sqlite3
import secrets
import io
from datetime import timedelta
from base64 import b64decode, b64encode

# Optional cryptography for AES-GCM decryption
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None

try:
    from flask_wtf import CSRFProtect
    from flask_wtf.csrf import generate_csrf
    csrf = CSRFProtect()
except Exception:
    csrf = None

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.permanent_session_lifetime = timedelta(days=7)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)
if csrf:
    app.config['WTF_CSRF_TIME_LIMIT'] = None
    csrf.init_app(app)
def maybe_csrf_exempt(func):
    return csrf.exempt(func) if csrf else func

# Feature flags (none for now)

try:
    iris = IRIS()
    cache = CacheManager()
    cache.init_database()
    print("✅ I.R.I.S and cache system initialized successfully")
except Exception as e:
    print(f"❌ Error initializing components: {e}")
    iris = None
    cache = None

# ===== File Processing / Encryption Helpers =====
def _get_or_create_upload_key() -> bytes:
    """Return per-session 32-byte key for AES-GCM. Creates if absent."""
    key_b64 = session.get('upload_key')
    if key_b64:
        try:
            return b64decode(key_b64)
        except Exception:
            pass
    key = os.urandom(32)
    session['upload_key'] = b64encode(key).decode('utf-8')
    return key

def _decrypt_file_payload(file_data: dict) -> str:
    """Decrypt encrypted file payload if present. Returns UTF-8 text content.

    Expected fields when encrypted: 'cipher' (base64), 'iv' (base64), 'algo' == 'AES-GCM'.
    """
    # If not encrypted, return provided content
    if not file_data or not isinstance(file_data, dict):
        return ''

    cipher_b64 = file_data.get('cipher')
    iv_b64 = file_data.get('iv')
    algo = (file_data.get('algo') or '').upper()
    raw_content = file_data.get('content')

    # If cipher not provided, assume plaintext in 'content'
    if not cipher_b64 or not iv_b64 or algo != 'AES-GCM':
        return (raw_content or '')

    if AESGCM is None:
        # cryptography not installed; cannot decrypt → fallback to empty
        return ''

    try:
        key = _get_or_create_upload_key()
        aesgcm = AESGCM(key)
        ct = b64decode(cipher_b64)
        iv = b64decode(iv_b64)
        pt = aesgcm.decrypt(iv, ct, None)
        return pt.decode('utf-8', errors='replace')
    except Exception as e:
        print(f"Error decrypting file payload: {e}")
        return ''
def _read_uploaded_file_storage(file_storage) -> str:
    """Read a Werkzeug FileStorage (multipart upload) and try extracting text.

    Returns a short description or extracted text wrapped for AI consumption.
    """
    try:
        name = getattr(file_storage, 'filename', 'upload') or 'upload'
        content_type = getattr(file_storage, 'mimetype', '') or ''
        data_bytes = file_storage.read() or b''
        file_storage.seek(0)

        # Text or JSON
        if content_type.startswith('text/') or content_type == 'application/json':
            try:
                txt = data_bytes.decode('utf-8', errors='replace')
            except Exception:
                txt = ''
            if txt:
                return f"📄 **{name}**\n```\n{txt}\n```"
            return f"📄 **{name}** (text file - empty)"

        # PDF
        if content_type == 'application/pdf':
            try:
                import pdfplumber
                extracted = ''
                if data_bytes:
                    with pdfplumber.open(io.BytesIO(data_bytes)) as pdf:
                        pages_text = []
                        for p in pdf.pages:
                            try:
                                pages_text.append(p.extract_text() or '')
                            except Exception:
                                pages_text.append('')
                        extracted = '\n'.join(pages_text).strip()
                if extracted:
                    return f"📄 **{name}** (PDF extracted)\n```\n{extracted}\n```"
                return f"📄 **{name}** (PDF file - content not extracted)"
            except Exception as ex:
                print(f"PDF extract failed (multipart) for {name}: {ex}")
                return f"📄 **{name}** (PDF file - content not extracted)"

        # Other known office types
        if content_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
            return f"📄 **{name}** (Word document - content not extracted)"
        if content_type in ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
            return f"📄 **{name}** (Excel spreadsheet - content not extracted)"

        # Fallback
        return f"📄 **{name}** (File type: {content_type})"
    except Exception as e:
        print(f"Error reading multipart file: {e}")
        return ''


def process_uploaded_files(files):
    """Process uploaded files and return formatted content for AI.

    Supports encrypted text/json payloads using AES-GCM from the frontend.
    """
    if not files:
        return ""
    
    file_contents = []
    
    for file_data in files:
        try:
            name = file_data.get('name', 'unknown')
            file_type = file_data.get('type', '')
            # Decrypt if encrypted, else use plaintext content
            content = _decrypt_file_payload(file_data)
            
            if not content:
                # For non-text types we still note presence
                if file_type and not (file_type.startswith('text/') or file_type == 'application/json'):
                    # Keep previous behavior: mention file without content extraction
                    if file_type == 'application/pdf':
                        file_contents.append(f"📄 **{name}** (PDF file - content not extracted)")
                    elif file_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                        file_contents.append(f"📄 **{name}** (Word document - content not extracted)")
                    elif file_type in ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
                        file_contents.append(f"📄 **{name}** (Excel spreadsheet - content not extracted)")
                    else:
                        file_contents.append(f"📄 **{name}** (File type: {file_type})")
                continue
                
            # Handle different file types
            if file_type.startswith('text/') or file_type == 'application/json':
                # Text files - content is already decoded
                file_contents.append(f"📄 **{name}**\n```\n{content}\n```")
                
            elif file_type == 'application/pdf':
                # Attempt to extract text from PDF content. Expect encrypted text to be
                # the original content string; for DataURL uploads we won't have bytes here.
                try:
                    import pdfplumber
                    # If content looks like a data URL, strip header
                    data = content
                    if isinstance(data, str) and data.startswith('data:'):
                        try:
                            header, b64 = data.split(',', 1)
                            data_bytes = b64decode(b64)
                        except Exception:
                            data_bytes = b''
                    elif isinstance(data, str):
                        # Try raw base64 without data URL prefix
                        try:
                            data_bytes = b64decode(data)
                        except Exception:
                            data_bytes = b''
                    else:
                        # content is expected to be text; not bytes. Nothing to parse.
                        data_bytes = b''

                    extracted = ''
                    if data_bytes:
                        with pdfplumber.open(io.BytesIO(data_bytes)) as pdf:
                            pages_text = []
                            for p in pdf.pages:
                                try:
                                    pages_text.append(p.extract_text() or '')
                                except Exception:
                                    pages_text.append('')
                            extracted = '\n'.join(pages_text).strip()

                    if extracted:
                        file_contents.append(f"📄 **{name}** (PDF extracted)\n```\n{extracted}\n```")
                    else:
                        # If we couldn't extract, just note the file
                        file_contents.append(f"📄 **{name}** (PDF file - content not extracted)")
                except Exception as ex:
                    print(f"PDF extract failed for {name}: {ex}")
                
            elif file_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                # Word documents
                file_contents.append(f"📄 **{name}** (Word document - content not extracted)")
                
            elif file_type in ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
                # Excel files
                file_contents.append(f"📄 **{name}** (Excel spreadsheet - content not extracted)")
                
            else:
                # Other file types (already handled if no content)
                file_contents.append(f"📄 **{name}** (File type: {file_type})")
                
        except Exception as e:
            print(f"Error processing file {file_data.get('name', 'unknown')}: {e}")
            continue
    
    if file_contents:
        return "**Uploaded Files:**\n\n" + "\n\n".join(file_contents)
    
    return ""

# File system operations removed along with File Manager feature

# ===== Auth storage (SQLite) =====
USERS_DB = os.path.join(os.path.dirname(__file__), 'iris_users.db')

def init_users_db():
    conn = sqlite3.connect(USERS_DB)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    # Conversations tables
    cur.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            title TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conv_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(conv_id) REFERENCES conversations(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(pw: str) -> str:
    try:
        import bcrypt
        return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    except Exception:
        import hashlib
        return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def create_user(username: str, password: str, role: str = 'user'):
    conn = sqlite3.connect(USERS_DB)
    cur = conn.cursor()
    cur.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', (username, hash_password(password), role))
    conn.commit()
    conn.close()

def find_user(username: str):
    conn = sqlite3.connect(USERS_DB)
    cur = conn.cursor()
    cur.execute('SELECT id, username, password_hash, role FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {'id': row[0], 'username': row[1], 'password_hash': row[2], 'role': row[3]}

def verify_password(raw_password: str, hashed: str) -> bool:
    try:
        import bcrypt
        return bcrypt.checkpw(raw_password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        import hashlib
        return hashlib.sha256(raw_password.encode('utf-8')).hexdigest() == hashed

init_users_db()

# Ensure default admin account for initial deployments
def ensure_default_admin():
    try:
        conn = sqlite3.connect(USERS_DB)
        cur = conn.cursor()
        cur.execute('SELECT 1 FROM users WHERE username = ?', ('OhuKyu',))
        exists = cur.fetchone()
        if not exists:
            cur.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', (
                'OhuKyu', hash_password('123456'), 'admin'
            ))
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ ensure_default_admin error: {e}")

ensure_default_admin()

# CSRF token helper for templates
@app.context_processor
def inject_csrf():
    def _csrf_token():
        if not csrf:
            return ''
        return generate_csrf()
    return dict(csrf_token=_csrf_token)

# ==== Conversation helpers ====
def create_conversation(username: str, title: str = None) -> int:
    conn = sqlite3.connect(USERS_DB)
    cur = conn.cursor()
    cur.execute('INSERT INTO conversations (username, title) VALUES (?, ?)', (username, title or 'New Conversation'))
    conv_id = cur.lastrowid
    conn.commit()
    conn.close()
    return conv_id

def add_message(conv_id: int, role: str, content: str) -> None:
    conn = sqlite3.connect(USERS_DB)
    cur = conn.cursor()
    cur.execute('INSERT INTO messages (conv_id, role, content) VALUES (?, ?, ?)', (conv_id, role, content))
    conn.commit()
    conn.close()

def list_conversations(username: str):
    conn = sqlite3.connect(USERS_DB)
    cur = conn.cursor()
    cur.execute('SELECT id, title, created_at FROM conversations WHERE username=? ORDER BY id DESC LIMIT 20', (username,))
    rows = cur.fetchall()
    conn.close()
    return [{'id': r[0], 'title': r[1], 'created_at': r[2]} for r in rows]

def rename_conversation(conv_id: int, username: str, title: str):
    conn = sqlite3.connect(USERS_DB)
    cur = conn.cursor()
    cur.execute('UPDATE conversations SET title=? WHERE id=? AND username=?', (title, conv_id, username))
    conn.commit()
    conn.close()

def delete_conversation(conv_id: int, username: str):
    conn = sqlite3.connect(USERS_DB)
    cur = conn.cursor()
    cur.execute('DELETE FROM messages WHERE conv_id=?', (conv_id,))
    cur.execute('DELETE FROM conversations WHERE id=? AND username=?', (conv_id, username))
    conn.commit()
    conn.close()

# ===== Global auth guard =====
@app.before_request
def enforce_authentication():
    path = request.path or '/'
    is_auth = bool(session.get('user'))
    public_paths = {'/login', '/register', '/health'}
    # Allow static files without authentication
    if path.startswith('/static/') or path.startswith('/css/') or path.startswith('/js/') or path.startswith('/images/'):
        return None
    # Refresh role from DB on every request so changes take effect immediately
    if is_auth:
        try:
            u = find_user(session.get('user'))
            if u:
                session['role'] = u.get('role', session.get('role', 'user'))
        except Exception:
            pass
    # Redirect authenticated users away from login/register
    if is_auth and path in {'/login', '/register'}:
        return redirect(url_for('index'))
    # Require auth for everything else
    if not is_auth and path not in public_paths:
        return redirect(url_for('login'))
    return None


@app.route('/health')
def health_check():
    """Health check endpoint for Railway"""
    if iris is None or cache is None:
        return jsonify({'status': 'unhealthy', 'message': 'Components not initialized'}), 503
    
    try:
        # Test cache connection
        cache.get_stats()
        return jsonify({
            'status': 'healthy',
            'message': 'I.R.I.S is running',
            'components': {
                'iris': 'ok',
                'cache': 'ok'
            }
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'message': str(e)}), 503

@app.route('/')
def index():
    if not session.get('user'):
        return redirect(url_for('login'))
    return render_template('index.html', role=session.get('role', 'user'), username=session.get('user'))

@app.route('/api/upload_key', methods=['GET'])
@maybe_csrf_exempt
def api_upload_key():
    """Provide per-session key for AES-GCM client-side encryption."""
    key = _get_or_create_upload_key()
    return jsonify({
        'algo': 'AES-GCM',
        'key': b64encode(key).decode('utf-8')
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data.get('username','').strip()
        password = data.get('password','')
        user = find_user(username)
        if not user or not verify_password(password, user['password_hash']):
            return render_template('login.html', error='Sai tài khoản hoặc mật khẩu')
        session['user'] = user['username']
        session['role'] = user['role']
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        username = data.get('username','').strip()
        password = data.get('password','')
        role = 'user'
        if not username or not password:
            return render_template('register.html', error='Vui lòng nhập đủ thông tin')
        try:
            create_user(username, password, role)
        except Exception as e:
            return render_template('register.html', error='Tên đăng nhập đã tồn tại')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    message = None
    # Actions
    if request.method == 'POST':
        action = request.form.get('action','update')
        username = request.form.get('username','').strip()
        conn = sqlite3.connect(USERS_DB)
        cur = conn.cursor()
        if action == 'delete' and username:
            cur.execute('DELETE FROM users WHERE username=?', (username,))
            message = f'Deleted user {username}'
        else:
            new_role = request.form.get('role','user')
            cur.execute('UPDATE users SET role=? WHERE username=?', (new_role, username))
            message = 'Updated role for ' + username
        conn.commit()
        conn.close()
    # fetch users with pagination and search
    page_size = 10
    try:
        page = max(int(request.args.get('page', '1')), 1)
    except Exception:
        page = 1
    q = (request.args.get('q') or '').strip()
    where = ''
    params = []
    if q:
        where = 'WHERE username LIKE ?'
        params.append(f'%{q}%')
    conn = sqlite3.connect(USERS_DB)
    cur = conn.cursor()
    cur.execute(f'SELECT COUNT(*) FROM users {where}', params)
    total = cur.fetchone()[0]
    offset = (page - 1) * page_size
    cur.execute(f'SELECT id, username, role, created_at FROM users {where} ORDER BY id DESC LIMIT ? OFFSET ?', params + [page_size, offset])
    users = cur.fetchall()
    conn.close()
    total_pages = max((total + page_size - 1) // page_size, 1)
    return render_template('admin.html', users=users, message=message, page=page, total_pages=total_pages, q=q, total_users=total)

@app.route('/api/cache/stats', methods=['GET'])
@maybe_csrf_exempt
def cache_stats():
    """Get cache statistics"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    try:
        stats = cache.get_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cache/clear', methods=['POST'])
@maybe_csrf_exempt
def clear_cache():
    """Clear all cache"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    try:
        cache.clear_all()
        return jsonify({'message': 'Cache cleared successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cache/clear-expired', methods=['POST'])
@maybe_csrf_exempt
def clear_expired_cache():
    """Clear expired cache entries"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    try:
        cache.clear_expired()
        return jsonify({'message': 'Expired cache cleared successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/explain', methods=['POST'])
@maybe_csrf_exempt
def api_explain():
    if iris is None:
        return jsonify({'error': 'I.R.I.S not initialized'}), 503
        
    try:
        data = request.get_json()
        question = data.get('question', '')
        if not question:
            return jsonify({'error': 'Question is required'}), 400
        
        result = iris.explain(question)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat', methods=['POST'])
@maybe_csrf_exempt
def api_chat():
    if iris is None:
        return jsonify({'error': 'I.R.I.S not initialized'}), 503
    try:
        # Support JSON or multipart/form-data
        message = ''
        files = []
        if request.content_type and request.content_type.startswith('multipart/form-data'):
            message = (request.form.get('message') or '').strip()
            # Extract text immediately and append into message
            extracted_blocks = []
            for _, fs in request.files.items():
                desc = _read_uploaded_file_storage(fs)
                if desc:
                    extracted_blocks.append(desc)
            if extracted_blocks:
                message = f"{message}\n\n".join([m for m in [message] if m]) + ("\n\n" if message else "") + "\n\n".join(extracted_blocks)
            # Do not pass files further; already merged into message
            files = []
        else:
            data = request.get_json() or {}
            message = (data.get('message') or '').strip()
            files = data.get('files', [])
        
        if not message and not files:
            return jsonify({'error': 'Message or files are required'}), 400
        
        # Process files and add to message
        file_content = ""
        if files:
            file_content = process_uploaded_files(files)
            if file_content:
                message = f"{message}\n\n{file_content}" if message else file_content
        
        # Conversation ensure
        conv_id = session.get('conv_id')
        if not conv_id:
            title = message[:60] if message else "File upload"
            conv_id = create_conversation(session.get('user'), title=title)
            session['conv_id'] = conv_id
        add_message(conv_id, 'user', message)
        result = iris.chat(message)
        add_message(conv_id, 'assistant', result)
        return jsonify({'result': result, 'conv_id': conv_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat/stream', methods=['POST'])
@maybe_csrf_exempt
def api_chat_stream():
    if iris is None:
        return Response('data: {"error":"I.R.I.S not initialized"}\n\n', mimetype='text/event-stream')
    try:
        # Support JSON or multipart/form-data
        files = []
        if request.content_type and request.content_type.startswith('multipart/form-data'):
            message = (request.form.get('message') or '').strip()
            extracted_blocks = []
            for _, fs in request.files.items():
                desc = _read_uploaded_file_storage(fs)
                if desc:
                    extracted_blocks.append(desc)
            if extracted_blocks:
                message = f"{message}\n\n".join([m for m in [message] if m]) + ("\n\n" if message else "") + "\n\n".join(extracted_blocks)
            files = []
        else:
            data = request.get_json(force=True, silent=True) or {}
            message = (data.get('message') or '').strip()
            files = data.get('files', [])
        
        if not message and not files:
            return Response('data: {"error":"Message or files are required"}\n\n', mimetype='text/event-stream')
        
        # Process files and add to message
        file_content = ""
        if files:
            file_content = process_uploaded_files(files)
            if file_content:
                message = f"{message}\n\n{file_content}" if message else file_content
        
        # ensure conversation
        conv_id = session.get('conv_id')
        if not conv_id:
            title = message[:60] if message else "File upload"
            conv_id = create_conversation(session.get('user'), title=title)
            session['conv_id'] = conv_id
        add_message(conv_id, 'user', message)

        def generate():
            buffer = ''
            for delta in iris.chat_stream(message):
                if not delta:
                    continue
                buffer += delta
                yield f'data: {json.dumps({"delta": delta})}\n\n'
            add_message(conv_id, 'assistant', buffer)
            yield f'data: {json.dumps({"done": True, "conv_id": conv_id})}\n\n'
        return Response(generate(), mimetype='text/event-stream')
    except Exception as e:
        return Response(f'data: {{"error":"{str(e)}"}}\n\n', mimetype='text/event-stream')

# File Manager API endpoints removed

# ===== Static Files Routes =====
@app.route('/css/<path:filename>')
def serve_css(filename):
    """Serve CSS files"""
    try:
        css_path = os.path.join(os.path.dirname(__file__), 'css', filename)
        if os.path.exists(css_path):
            with open(css_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return Response(content, mimetype='text/css')
        else:
            return "CSS file not found", 404
    except Exception as e:
        return f"Error serving CSS: {str(e)}", 500

@app.route('/js/<path:filename>')
def serve_js(filename):
    """Serve JavaScript files"""
    try:
        js_path = os.path.join(os.path.dirname(__file__), 'js', filename)
        if os.path.exists(js_path):
            with open(js_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return Response(content, mimetype='application/javascript')
        else:
            return "JS file not found", 404
    except Exception as e:
        return f"Error serving JS: {str(e)}", 500

@app.route('/images/<path:filename>')
def serve_images(filename):
    """Serve image files"""
    try:
        img_path = os.path.join(os.path.dirname(__file__), 'images', filename)
        if os.path.exists(img_path):
            return send_file(img_path)
        else:
            return "Image file not found", 404
    except Exception as e:
        return f"Error serving image: {str(e)}", 500

@app.route('/api/conversations/new', methods=['POST'])
@maybe_csrf_exempt
def api_new_conversation():
    conv_id = create_conversation(session.get('user'))
    session['conv_id'] = conv_id
    return jsonify({'conv_id': conv_id})

@app.route('/api/conversations', methods=['GET'])
@maybe_csrf_exempt
def api_list_conversations():
    items = list_conversations(session.get('user'))
    return jsonify({'items': items})

@app.route('/api/conversations/set', methods=['POST'])
@maybe_csrf_exempt
def api_set_conversation():
    data = request.get_json() or {}
    conv_id = int(data.get('conv_id', 0))
    session['conv_id'] = conv_id
    return jsonify({'ok': True})

@app.route('/api/conversations/<int:conv_id>/messages', methods=['GET'])
@maybe_csrf_exempt
def api_get_messages(conv_id: int):
    conn = sqlite3.connect(USERS_DB)
    cur = conn.cursor()
    cur.execute('SELECT role, content, created_at FROM messages WHERE conv_id=? ORDER BY id ASC', (conv_id,))
    rows = cur.fetchall()
    conn.close()
    msgs = [{ 'role': r[0], 'content': r[1], 'created_at': r[2] } for r in rows]
    return jsonify({'items': msgs})

@app.route('/api/conversations/rename', methods=['POST'])
@maybe_csrf_exempt
def api_rename_conversation():
    data = request.get_json() or {}
    conv_id = int(data.get('conv_id', 0))
    title = (data.get('title') or '').strip()
    if not conv_id or not title:
        return jsonify({'error': 'Missing parameters'}), 400
    rename_conversation(conv_id, session.get('user'), title)
    return jsonify({'ok': True})

@app.route('/api/conversations/delete', methods=['POST'])
@maybe_csrf_exempt
def api_delete_conversation():
    data = request.get_json() or {}
    conv_id = int(data.get('conv_id', 0))
    if not conv_id:
        return jsonify({'error': 'Missing conv_id'}), 400
    delete_conversation(conv_id, session.get('user'))
    # reset current selection
    if session.get('conv_id') == conv_id:
        session.pop('conv_id', None)
    return jsonify({'ok': True})

@app.route('/api/summarize', methods=['POST'])
@maybe_csrf_exempt
def api_summarize():
    try:
        data = request.get_json()
        text = data.get('text', '')
        ratio = data.get('ratio', 0.4)
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        result = iris.summarize(text, ratio)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/explain_code', methods=['POST'])
@maybe_csrf_exempt
def api_explain_code():
    try:
        data = request.get_json()
        code = data.get('code', '')
        language = data.get('language', 'python')
        
        if not code:
            return jsonify({'error': 'Code is required'}), 400
        
        result = iris.explain_code(code, language)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/flashcards', methods=['POST'])
@maybe_csrf_exempt
def api_flashcards():
    try:
        data = request.get_json()
        text = data.get('text', '')
        n = data.get('n', 5)
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        flashcards = iris.make_flashcards(text, n)
        result = [{'front': card.front, 'back': card.back} for card in flashcards]
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/quiz', methods=['POST'])
@maybe_csrf_exempt
def api_quiz():
    try:
        data = request.get_json()
        text = data.get('text', '')
        n = data.get('n', 3)
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        quiz_items = iris.quiz(text, n)
        result = [{
            'question': item.question,
            'options': item.options,
            'answer': item.answer,
            'explanation': item.explanation
        } for item in quiz_items]
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/study_plan', methods=['POST'])
@maybe_csrf_exempt
def api_study_plan():
    try:
        data = request.get_json()
        goal = data.get('goal', '')
        days = data.get('days', 7)
        hours = data.get('hours', 2)
        
        if not goal:
            return jsonify({'error': 'Goal is required'}), 400
        
        result = iris.study_plan(goal, days, hours)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting I.R.I.S for Render deployment...")
    
    port = int(os.environ.get('PORT', 5000))
    is_render = os.environ.get('RENDER_ENVIRONMENT') == 'production'
    debug = not is_render
    
    print(f"🌐 Server starting on port {port}")
    print(f"🔧 Debug mode: {debug}")
    print(f"🏗️ Platform: {'Render' if is_render else 'Local'}")
    
    app.run(debug=debug, host='0.0.0.0', port=port)
