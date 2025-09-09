from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response
from iris import IRIS
from cache_manager import CacheManager
import json
import os
import sqlite3
import secrets
from datetime import timedelta
from functools import wraps

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

try:
    iris = IRIS()
    cache = CacheManager()
    cache.init_database()
    print("✅ I.R.I.S and cache system initialized successfully")
except Exception as e:
    print(f"❌ Error initializing components: {e}")
    iris = None
    cache = None

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
    if path.startswith('/static/'):
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
        data = request.get_json()
        message = data.get('message', '')
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        # Conversation ensure
        conv_id = session.get('conv_id')
        if not conv_id:
            conv_id = create_conversation(session.get('user'), title=message[:60])
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
        data = request.get_json(force=True, silent=True) or {}
        message = (data.get('message') or '').strip()
        if not message:
            return Response('data: {"error":"Message is required"}\n\n', mimetype='text/event-stream')
        # ensure conversation
        conv_id = session.get('conv_id')
        if not conv_id:
            conv_id = create_conversation(session.get('user'), title=message[:60])
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
