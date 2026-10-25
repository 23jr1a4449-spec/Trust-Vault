import os
import hashlib
import csv
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'trustvault-secure-production-key'

# Store SQLite database in the main project folder for easy local access
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'trustvault.db')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'txt', 'png', 'jpg', 'jpeg', 'docx'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'Admin' or 'Viewer'

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    filepath = db.Column(db.String(300), nullable=False)
    file_hash = db.Column(db.String(64), nullable=True)  # SHA-256 binary hash of the uploaded file
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(150), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.String(300), nullable=True)
    previous_hash = db.Column(db.String(64), nullable=False)
    current_hash = db.Column(db.String(64), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- HELPER FUNCTIONS ---

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def log_event(user, action, details=""):
    last_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev_hash = last_log.current_hash if last_log else "0" * 64
    
    timestamp_str = datetime.utcnow().isoformat()
    raw_data = f"{prev_hash}{user.id}{action}{timestamp_str}{details}"
    curr_hash = hashlib.sha256(raw_data.encode()).hexdigest()

    new_log = AuditLog(
        user_id=user.id,
        username=user.username,
        action=action,
        details=details,
        previous_hash=prev_hash,
        current_hash=curr_hash
    )
    db.session.add(new_log)
    db.session.commit()

# --- ROUTES ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            log_event(user, "USER_LOGIN", f"User {username} authenticated successfully.")
            return redirect(url_for('dashboard'))
        flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_event(current_user, "USER_LOGOUT", f"User {current_user.username} terminated session.")
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    documents = Document.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    # Tolerant cryptographic chain verification for UI dashboard
    all_logs = AuditLog.query.order_by(AuditLog.id.asc()).all()
    chain_is_valid = True
    
    if len(all_logs) > 1:
        for i in range(1, len(all_logs)):
            curr_log = all_logs[i]
            raw_data = f"{curr_log.previous_hash}{curr_log.user_id}{curr_log.action}{curr_log.timestamp.isoformat()}{curr_log.details or ''}"
            recalculated_hash = hashlib.sha256(raw_data.encode()).hexdigest()
            if curr_log.current_hash != recalculated_hash:
                chain_is_valid = False
                break

    return render_template('dashboard.html', documents=documents, logs=logs, chain_is_valid=chain_is_valid)

@app.route('/upload', methods=['POST'])
@login_required
def upload_document():
    if current_user.role != 'Admin':
        log_event(current_user, "UNAUTHORIZED_ACCESS_ATTEMPT", "Blocked unauthorized file upload attempt.")
        abort(403)

    if 'file' not in request.files:
        flash('No file part selected in request.', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected for uploading.', 'danger')
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp_prefix = datetime.utcnow().strftime('%Y%m%d%H%M%S_')
        unique_filename = timestamp_prefix + filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(filepath)
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash_str = sha256_hash.hexdigest()

        new_doc = Document(
            filename=filename, 
            filepath=unique_filename, 
            file_hash=file_hash_str,
            uploader_id=current_user.id
        )
        db.session.add(new_doc)
        db.session.commit()

        log_event(current_user, "DOCUMENT_UPLOADED", f"Successfully uploaded file: {filename}")
        flash('Document uploaded securely with SHA-256 cryptographic hashing.', 'success')
    else:
        flash('Invalid file format. Allowed extensions: pdf, txt, png, jpg, jpeg, docx', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/download/<int:doc_id>')
@login_required
def download_document(doc_id):
    doc = db.session.get(Document, doc_id)
    if not doc:
        abort(404)

    log_event(current_user, "DOCUMENT_DOWNLOADED", f"Accessed and downloaded file: {doc.filename}")
    return send_from_directory(app.config['UPLOAD_FOLDER'], doc.filepath, as_attachment=True)

@app.route('/verify-audit-trail')
@login_required
def verify_audit_trail():
    if current_user.role != 'Admin':
        abort(403)
    
    logs = AuditLog.query.order_by(AuditLog.id.asc()).all()
    is_valid = True
    compromised_log_id = None
    
    if len(logs) > 1:
        for i in range(1, len(logs)):
            curr_log = logs[i]
            raw_data = f"{curr_log.previous_hash}{curr_log.user_id}{curr_log.action}{curr_log.timestamp.isoformat()}{curr_log.details or ''}"
            recalculated_hash = hashlib.sha256(raw_data.encode()).hexdigest()
            
            if curr_log.current_hash != recalculated_hash:
                is_valid = False
                compromised_log_id = curr_log.id
                break
        
    return render_template('verify.html', is_valid=is_valid, compromised_log_id=compromised_log_id)

@app.route('/export-logs')
@login_required
def export_logs():
    if current_user.role != 'Admin':
        abort(403)
    
    log_event(current_user, "AUDIT_LOGS_EXPORTED", "Exported tamper-evident audit trail report as CSV.")
    
    logs = AuditLog.query.all()
    output = []
    output.append(['ID', 'Timestamp (UTC)', 'Username', 'Action', 'Details', 'Current Hash'])
    
    for l in logs:
        output.append([l.id, l.timestamp.isoformat(), l.username, l.action, l.details, l.current_hash])
        
    csv_data = "\n".join([",".join(map(str, row)) for row in output])
    
    response = make_response(csv_data)
    response.headers["Content-Disposition"] = "attachment; filename=trustvault_audit_trail_report.csv"
    response.headers["Content-Type"] = "text/csv"
    return response

# --- INITIALIZE DB & DEFAULT USERS ---
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', password=generate_password_hash('admin123'), role='Admin')
        viewer_user = User(username='viewer', password=generate_password_hash('viewer123'), role='Viewer')
        db.session.add_all([admin_user, viewer_user])
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)