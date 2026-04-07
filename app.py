
"app.py — CyberScan AI"

import json
import os
import queue
import threading
import time
import uuid
from datetime import datetime
from functools import wraps

from flask import (Flask, Response, flash, jsonify, redirect,
                   render_template, request, send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import database as db
from config import Config
from ml_classifier import severity_color, severity_rank
from scanner_engine import run_scan

# ── App setup ────────────────────────────────────
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

# In-memory store for SSE scan streams  {scan_token: Queue}
_scan_queues: dict[str, queue.Queue] = {}
_scan_results: dict[str, list] = {}

with app.app_context():
    db.init_db()


# ── Auth helpers ─────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def current_user():
    uid = session.get('user_id')
    if uid:
        return db.get_user_by_id(uid)
    return None


# ── Template context ─────────────────────────────

@app.context_processor
def inject_globals():
    return {
        'user': current_user(),
        'now': datetime.utcnow(),
        'severity_color': severity_color,
    }


# ── Auth routes ──────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = db.get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm', '')

        if len(username) < 3:
            flash('Username must be at least 3 characters.', 'danger')
        elif len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
        elif password != confirm:
            flash('Passwords do not match.', 'danger')
        else:
            pw_hash = generate_password_hash(password)
            if db.create_user(username, pw_hash):
                flash('Account created! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Username already taken.', 'danger')
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ── Dashboard ────────────────────────────────────

@app.route('/')
@login_required
def dashboard():
    uid = session['user_id']
    recent = db.get_scans_by_user(uid, limit=10)
    stats_rows, total = db.get_scan_stats(uid)
    distinct_targets = db.get_distinct_targets(uid)
    high_critical = db.get_high_critical_count(uid)

    # Build chart data
    sev_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    vuln_counts = {}
    for row in stats_rows:
        sev = row['severity'] if row['severity'] in sev_counts else 'Info'
        sev_counts[sev] += row['cnt']
        vuln_counts[row['vulnerability']] = vuln_counts.get(row['vulnerability'], 0) + row['cnt']

    return render_template(
        'dashboard.html',
        recent=recent,
        total=total,
        sev_counts=sev_counts,
        vuln_counts=vuln_counts,
        distinct_targets=distinct_targets,
        high_critical=high_critical,
    )


# ── Static pages ─────────────────────────────────

@app.route('/about')
@login_required
def about():
    return render_template('about.html')


@app.route('/how-it-works')
@login_required
def how_it_works():
    return render_template('how_it_works.html')


# ── Tools Hub ────────────────────────────────────

@app.route('/tools')
@login_required
def tools():
    return render_template('tools.html')


@app.route('/api/fetch-headers', methods=['POST'])
@login_required
def api_fetch_headers():
    """Fetch HTTP response headers for Tools > Header Inspector."""
    import requests as req_lib
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL required'}), 400
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://' + url
    try:
        r = req_lib.get(url, timeout=6, allow_redirects=True,
                        headers={'User-Agent': 'CyberScanAI/1.0'})
        headers = dict(r.headers)
        return jsonify({'status': r.status_code, 'headers': headers})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Profile / Settings ───────────────────────────

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    uid = session['user_id']
    _, total_scans = db.get_scan_stats(uid)
    distinct_targets = db.get_distinct_targets(uid)
    high_critical = db.get_high_critical_count(uid)
    settings = db.get_user_settings(uid)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'change_password':
            current_pw = request.form.get('current_password', '')
            new_pw     = request.form.get('new_password', '')
            confirm_pw = request.form.get('confirm_password', '')
            user = db.get_user_by_id(uid)
            if not check_password_hash(user['password'], current_pw):
                flash('Current password is incorrect.', 'danger')
            elif len(new_pw) < 6:
                flash('New password must be at least 6 characters.', 'danger')
            elif new_pw != confirm_pw:
                flash('New passwords do not match.', 'danger')
            else:
                db.update_user_password(uid, generate_password_hash(new_pw))
                flash('Password updated successfully!', 'success')

        elif action == 'save_settings':
            email_alerts = 1 if request.form.get('email_alerts') else 0
            scan_mode    = request.form.get('default_scan_mode', 'full')
            db.save_user_settings(uid, email_alerts, scan_mode)
            flash('Settings saved!', 'success')

        return redirect(url_for('profile'))

    return render_template(
        'profile.html',
        total_scans=total_scans,
        distinct_targets=distinct_targets,
        high_critical=high_critical,
        settings=settings,
    )


# ── Scan Notes API ───────────────────────────────

@app.route('/api/notes', methods=['POST'])
@login_required
def api_save_note():
    data = request.get_json(silent=True) or {}
    url  = data.get('url', '').strip()
    note = data.get('note', '').strip()
    if not url or not note:
        return jsonify({'error': 'url and note are required'}), 400
    note_id = db.save_note(session['user_id'], url, note)
    return jsonify({'id': note_id, 'message': 'Note saved'})


@app.route('/api/notes', methods=['GET'])
@login_required
def api_get_notes():
    url = request.args.get('url', '').strip()
    uid = session['user_id']
    if url:
        notes = db.get_notes_by_url(uid, url)
    else:
        notes = db.get_notes_by_user(uid)
    return jsonify({'notes': notes})


@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@login_required
def api_delete_note(note_id):
    db.delete_note(note_id, session['user_id'])
    return jsonify({'message': 'Note deleted'})


# ── Clear History API ────────────────────────────

@app.route('/api/clear-history', methods=['POST'])
@login_required
def api_clear_history():
    db.clear_scan_history(session['user_id'])
    return jsonify({'message': 'History cleared'})


# ── Scan ─────────────────────────────────────────

@app.route('/scan')
@login_required
def scan_page():
    return render_template('scan.html')


@app.route('/scan/start', methods=['POST'])
@login_required
def scan_start():
    url = request.form.get('url', '').strip()
    if not url:
        flash('Please provide a target URL.', 'danger')
        return redirect(url_for('scan_page'))
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url

    token = str(uuid.uuid4())
    q = queue.Queue()
    _scan_queues[token] = q
    _scan_results[token] = None

    # Capture uid HERE in request context — sessions are NOT available inside threads
    uid = session['user_id']

    def worker():
        def emit(msg):
            q.put(('log', msg))

        findings = run_scan(url, progress_callback=emit)

        # Save every finding to DB
        if findings:
            for f in findings:
                db.save_scan(uid, url, f['vulnerability'], f['severity'],
                             f.get('details', ''), f.get('remediation', ''))
        else:
            db.save_scan(uid, url, 'No Vulnerabilities', 'Info',
                         'No issues detected during automated scan.', '')

        _scan_results[token] = {'url': url, 'findings': findings}
        q.put(('done', token))

    threading.Thread(target=worker, daemon=True).start()
    return render_template('scan.html', streaming=True, token=token, target_url=url)


@app.route('/scan/stream/<token>')
@login_required
def scan_stream(token):
    q = _scan_queues.get(token)
    if not q:
        return Response('data: [!] Invalid scan token\n\n', mimetype='text/event-stream')

    def generate():
        last_ping = time.time()
        while True:
            try:
                evt, data = q.get(timeout=15)
                if evt == 'log':
                    yield f"data: {data}\n\n"
                elif evt == 'done':
                    yield f"event: done\ndata: {data}\n\n"
                    break
            except queue.Empty:
                # Send heartbeat ping to keep connection alive
                if time.time() - last_ping > 120:
                    yield "data: [!] Scan timed out after 2 minutes.\n\n"
                    break
                yield ": heartbeat\n\n"
                last_ping = time.time()

    return Response(generate(), mimetype='text/event-stream',
                    headers={'X-Accel-Buffering': 'no',
                             'Cache-Control': 'no-cache',
                             'Connection': 'keep-alive'})


@app.route('/results/<token>')
@login_required
def results(token):
    data = _scan_results.get(token)
    if not data:
        flash('Scan results not found or expired.', 'warning')
        return redirect(url_for('scan_page'))

    findings = sorted(data['findings'],
                      key=lambda x: severity_rank(x['severity']), reverse=True)
    return render_template('results.html', target=data['url'], findings=findings, token=token)


# ── History ──────────────────────────────────────

@app.route('/history')
@login_required
def history():
    uid = session['user_id']
    scans = db.get_scans_by_user(uid)
    return render_template('history.html', scans=scans)


# ── Reports ──────────────────────────────────────

def _user_report_dir():
    """Return and create reports/<username>/ directory for the current user."""
    username = session.get('username', 'unknown')
    # Sanitise username for filesystem use
    safe_name = ''.join(c for c in username if c.isalnum() or c in ('_', '-'))
    user_dir = os.path.join(Config.REPORTS_DIR, safe_name)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir, safe_name


@app.route('/report/<token>/json')
@login_required
def report_json(token):
    data = _scan_results.get(token)
    if not data:
        return jsonify({'error': 'Results not found'}), 404

    user_dir, username = _user_report_dir()
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f'{username}_{ts}_{token[:8]}.json'

    report = {
        'tool': 'CyberScan AI',
        'generated_by': username,
        'target': data['url'],
        'scan_date': datetime.utcnow().isoformat() + 'Z',
        'total_findings': len(data['findings']),
        'findings': data['findings'],
    }
    path = os.path.join(user_dir, filename)
    with open(path, 'w') as fh:
        json.dump(report, fh, indent=2)

    return send_file(path, as_attachment=True,
                     download_name=filename,
                     mimetype='application/json')


@app.route('/report/<token>/pdf')
@login_required
def report_pdf(token):
    data = _scan_results.get(token)
    if not data:
        flash('Results not found or scan expired. Please re-run the scan before downloading.', 'warning')
        return redirect(url_for('dashboard'))

    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos

        def safe(text):
            """Replace common Unicode chars with ASCII equivalents so Helvetica (latin-1) doesn't crash."""
            if not text:
                return ''
            replacements = {
                '\u2014': '-',  # em-dash
                '\u2013': '-',  # en-dash
                '\u2018': "'",  # left single quote
                '\u2019': "'",  # right single quote
                '\u201c': '"',  # left double quote
                '\u201d': '"',  # right double quote
                '\u2026': '...', # ellipsis
                '\u2022': '-',  # bullet
                '\u2192': '->',  # right arrow
                '\u2190': '<-',  # left arrow
                '\u00e2\u0080\u0094': '-',  # utf-8 em-dash mis-decoded
            }
            for char, replacement in replacements.items():
                text = text.replace(char, replacement)
            return text.encode('latin-1', errors='replace').decode('latin-1')

        # Ensure reports directory exists
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_margins(left=15, top=15, right=15)
        pdf.add_page()

        # ── Header ──────────────────────────────────
        pdf.set_font('Helvetica', 'B', 20)
        pdf.set_text_color(0, 180, 90)
        pdf.cell(0, 12, safe('CyberScan AI - Vulnerability Report'),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')

        pdf.set_text_color(80, 80, 80)
        pdf.set_font('Helvetica', '', 10)
        pdf.cell(0, 7, safe(f"Target: {data['url']}"),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        pdf.cell(0, 7, f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        pdf.ln(4)

        # ── Divider ──────────────────────────────────
        pdf.set_draw_color(0, 180, 90)
        pdf.set_line_width(0.5)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(5)

        # ── Summary ──────────────────────────────────
        pdf.set_font('Helvetica', 'B', 13)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 9, f"Total Findings: {len(data['findings'])}",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

        SEV_COLORS = {
            'Critical': (220, 50,  50),
            'High':     (220, 140,  0),
            'Medium':   (200, 170,  0),
            'Low':      (0,  140, 200),
            'Info':     (110, 110, 110),
        }

        for idx, finding in enumerate(data['findings'], 1):
            sev = finding.get('severity', 'Info')
            r, g, b = SEV_COLORS.get(sev, (100, 100, 100))

            # Finding title
            pdf.set_font('Helvetica', 'B', 12)
            pdf.set_text_color(r, g, b)
            title = safe(f"{idx}. {finding.get('vulnerability','Unknown')} [{sev}]")
            pdf.cell(0, 9, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Parameter
            if finding.get('parameter') and finding['parameter'] != 'HTTP Header':
                pdf.set_font('Helvetica', '', 9)
                pdf.set_text_color(80, 80, 80)
                pdf.cell(0, 6, safe(f"Parameter: {finding['parameter']}"),
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Details
            pdf.set_font('Helvetica', '', 10)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 6, safe(f"Details: {finding.get('details','')}"),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Remediation
            if finding.get('remediation'):
                pdf.set_font('Helvetica', 'I', 9)
                pdf.set_text_color(80, 80, 80)
                pdf.multi_cell(0, 5, safe(f"Fix: {finding['remediation']}"),
                               new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.ln(4)

            # Light separator between findings
            pdf.set_draw_color(220, 220, 220)
            pdf.set_line_width(0.2)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(4)

        # ── Footer ────────────────────────────────────
        pdf.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(160, 160, 160)
        pdf.cell(0, 8,
                 'Generated by CyberScan AI | For authorised penetration testing only.',
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')

        user_dir, username = _user_report_dir()
        ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f'{username}_{ts}_{token[:8]}.pdf'
        path = os.path.join(user_dir, filename)
        pdf.output(path)

        return send_file(path, as_attachment=True,
                         download_name=filename,
                         mimetype='application/pdf')

    except ImportError:
        flash('fpdf2 not installed. Run: pip install fpdf2', 'warning')
        return redirect(url_for('results', token=token))
    except Exception as e:
        flash(f'PDF generation failed: {str(e)}', 'danger')
        return redirect(url_for('results', token=token))



# ── Run ──────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=Config.DEBUG, threaded=True)