import os
import json
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, render_template, redirect, url_for,
    send_file, jsonify, make_response, session
)

from core.protector import protect
from core.ciphers import CIPHERS

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = Path(__file__).parent / 'uploads'
app.config['OUTPUT_FOLDER'] = Path(__file__).parent / 'output'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']
OUTPUT_FOLDER = app.config['OUTPUT_FOLDER']
UPLOAD_FOLDER.mkdir(exist_ok=True)
OUTPUT_FOLDER.mkdir(exist_ok=True)

DEV1_USER = '𝓙𝓸𝓴𝓮𝓻丨𝓜4'
DEV1_PASS = hashlib.sha256('VT_YC'.encode()).hexdigest()
DEV2_USER = 'آسِـتٌـٕنِـْجّـآيَـٰٕهّ✨'
DEV2_PASS = hashlib.sha256('Sting_vip2'.encode()).hexdigest()

ADMIN_CREDS = {DEV1_USER: DEV1_PASS, DEV2_USER: DEV2_PASS}
LOG_FILE = OUTPUT_FOLDER / 'access.json'


def _log(action, detail='', ip=''):
    entry = {
        'time': datetime.utcnow().isoformat(),
        'action': action,
        'detail': detail,
        'ip': ip,
    }
    logs = []
    if LOG_FILE.exists():
        logs = json.loads(LOG_FILE.read_text())
    logs.append(entry)
    if len(logs) > 500:
        logs = logs[-500:]
    LOG_FILE.write_text(json.dumps(logs, indent=2))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    return render_template('index.html', ciphers=CIPHERS)


@app.route('/protect', methods=['POST'])
def protect_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if not f.filename.endswith('.py'):
        return jsonify({'error': 'Only .py files allowed'}), 400

    cipher_ids = request.form.getlist('ciphers')
    if not cipher_ids:
        cipher_ids = ['aes']

    obfuscate_flags = {
        'rename': request.form.get('obf_rename', 'false') == 'true',
        'strip_docs': request.form.get('obf_strip', 'false') == 'true',
        'deadcode': request.form.get('obf_deadcode', 'false') == 'true',
        'encode_strings_flag': request.form.get('obf_encstr', 'false') == 'true',
        'misleading_imports': request.form.get('obf_fakeimports', 'false') == 'true',
        'anti_debug': request.form.get('obf_antidebug', 'false') == 'true',
    }

    source = f.read().decode('utf-8')
    try:
        result = protect(source, cipher_ids=cipher_ids, obfuscate_flags=obfuscate_flags)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    fid = uuid.uuid4().hex
    out_path = OUTPUT_FOLDER / f'{fid}.py'
    out_path.write_text(result['loader'])

    _log('protect', f'{f.filename} -> {fid}.py [{", ".join(result["layers"])}]', request.remote_addr or '')

    history_file = OUTPUT_FOLDER / 'history.json'
    history = []
    if history_file.exists():
        history = json.loads(history_file.read_text())
    history.append({
        'id': fid,
        'filename': f.filename,
        'layers': result['layers'],
        'size': len(result['loader']),
        'ciphers': cipher_ids,
        'time': datetime.utcnow().isoformat(),
        'ip': request.remote_addr or '',
    })
    if len(history) > 200:
        history = history[-200:]
    history_file.write_text(json.dumps(history, indent=2))

    return jsonify({
        'file_id': fid,
        'layers': result['layers'],
        'size': len(result['loader']),
    })


@app.route('/download/<file_id>')
def download(file_id):
    out_path = OUTPUT_FOLDER / f'{file_id}.py'
    if not out_path.exists():
        return jsonify({'error': 'File not found'}), 404
    _log('download', file_id, request.remote_addr or '')
    return send_file(
        str(out_path),
        as_attachment=True,
        download_name='protected.py',
        mimetype='text/x-python',
    )


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username in ADMIN_CREDS and hashlib.sha256(password.encode()).hexdigest() == ADMIN_CREDS[username]:
            session['user'] = username
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=2)
            return redirect(url_for('admin_dashboard'))
        return render_template('admin.html', error='Invalid credentials', login=True)
    return render_template('admin.html', login=True)


@app.route('/admin/logout')
def admin_logout():
    session.pop('user', None)
    return redirect(url_for('admin_login'))


@app.route('/admin')
@login_required
def admin_dashboard():
    logs = []
    if LOG_FILE.exists():
        logs = json.loads(LOG_FILE.read_text())

    history = []
    history_file = OUTPUT_FOLDER / 'history.json'
    if history_file.exists():
        history = json.loads(history_file.read_text())

    stats = {
        'total_protections': sum(1 for l in logs if l['action'] == 'protect'),
        'total_downloads': sum(1 for l in logs if l['action'] == 'download'),
        'unique_ips': len(set(l.get('ip', '') for l in logs if l.get('ip'))),
    }
    return render_template(
        'admin.html',
        user=session['user'],
        logs=logs[-100:],
        stats=stats,
        history=history[-50:],
        login=False,
    )


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
