from flask import Flask, render_template, request, send_file, session, redirect
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from datetime import datetime
import sqlite3
import hashlib
import io
import base64
import os
import uuid
import json
from dotenv import load_dotenv
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename

load_dotenv()
app = Flask(__name__)
from dotenv import load_dotenv
import os

load_dotenv()
app.secret_key = os.getenv("SECRET_KEY")
HR_USERNAME = os.getenv("HR_USERNAME")
HR_PASSWORD = os.getenv("HR_PASSWORD")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
# =======================
# MAIL CONFIGURATION
# =======================
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed_files"
DB_NAME = "esignature.db"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)



# =======================
# JSON FIELD STORAGE
# =======================

def get_fields_file(doc_id):
    return f"fields_{doc_id}.json"

def load_fields(doc_id):
    path = get_fields_file(doc_id)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []

def save_fields_json(doc_id, data):
    with open(get_fields_file(doc_id), "w") as f:
        json.dump(data, f)


# =======================
# DATABASE INIT
# =======================

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            filename TEXT,
            status TEXT,
            created_at TEXT,
            integrity_hash TEXT,
            email TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS signed_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT,
            employee_id TEXT,
            signer_name TEXT,
            version INTEGER,
            signed_file BLOB,
            signed_hash TEXT,
            file_path TEXT,
            signed_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT,
            employee_id TEXT,
            action TEXT,
            timestamp TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS hr_allowed_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE
        )
    """)

    conn.commit()
    conn.close()


# =======================
# LOGIN
# =======================

@app.route("/hr-login", methods=["GET", "POST"])
def hr_login():
    error = None
    if request.method == "POST":
        if request.form.get("username") == HR_USERNAME and request.form.get("password") == HR_PASSWORD:
            session["hr_logged_in"] = True
            return redirect("/admin")
        error = "Invalid username or password"
    return render_template("hr_login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/hr-login")


# =======================
# ADMIN DASHBOARD
# =======================

@app.route("/admin")
def admin():
    if not session.get("hr_logged_in"):
        return redirect("/hr-login")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, filename, status, created_at, email FROM documents ORDER BY created_at DESC")
    documents = c.fetchall()
    conn.close()

    return render_template("admin.html", documents=documents)


@app.route("/upload_pdf", methods=["POST"])
def upload_pdf():
    if not session.get("hr_logged_in"):
        return "Unauthorized", 403

    file = request.files["pdf"]
    email = request.form.get("email", "").strip()

    # Validate email is provided
    if not email:
        return "Email is required", 400

    if file:
        # Clean filename (removes &, spaces, etc.)
        original_name = secure_filename(file.filename)

        # Add UUID to avoid duplicates
        unique_name = str(uuid.uuid4()) + "_" + original_name

        path = os.path.join(UPLOAD_FOLDER, unique_name)
        file.save(path)

        with open(path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        doc_id = str(uuid.uuid4())

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("""
            INSERT INTO documents (id, filename, status, created_at, integrity_hash, email)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (doc_id, unique_name, "Draft", datetime.now().isoformat(), file_hash, email))
        conn.commit()
        conn.close()

    return redirect("/admin")

@app.route("/admin/design/<doc_id>")
def design_fields(doc_id):
    if not session.get("hr_logged_in"):
        return redirect("/hr-login")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT filename FROM documents WHERE id=?", (doc_id,))
    record = c.fetchone()
    conn.close()

    if not record:
        return "Not Found", 404

    filename = record[0]
    fields = load_fields(doc_id)

    return render_template("design.html",
                           doc_id=doc_id,
                           filename=filename,
                           fields=fields)


@app.route("/admin/save_fields/<doc_id>", methods=["POST"])
def save_fields(doc_id):
    if not session.get("hr_logged_in"):
        return "Unauthorized", 403

    data = request.json
    save_fields_json(doc_id, data)
    return {"status": "saved"}


@app.route("/admin/send/<doc_id>")
def send_document(doc_id):
    if not session.get("hr_logged_in"):
        return redirect("/hr-login")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT email, filename FROM documents WHERE id=?", (doc_id,))
    record = c.fetchone()

    if not record:
        conn.close()
        return "Document not found", 404

    recipient_email, filename = record

    if not recipient_email:
        conn.close()
        return "No recipient email found for this document", 400

    # Create the signing link
    # In a real environment, replace 'http://127.0.0.1:5000' with your actual domain
    base_url = request.url_root.rstrip('/')
    sign_link = f"{base_url}/sign/{doc_id}"

    # Send the email
    try:
        msg = Message(
            subject="Aaptatt invites you to review/sign this document",
            recipients=[recipient_email]
        )
        
        # Professional Plain Text Version (Fallback)
        msg.body = f"""
Dear recipient,

Aaptatt has invited you to review and electronically sign a document.

Please view and sign the document via the following link:
{sign_link}

Best regards,
Aaptatt Human Resources
"""

        # Professional HTML Version
        msg.html = f"""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 40px; background-color: #f8fafc; color: #1e293b; line-height: 1.6;">
            <div style="background-color: #ffffff; padding: 40px; border-radius: 16px; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                <div style="text-align: left; border-bottom: 2px solid #6366f1; padding-bottom: 20px; margin-bottom: 30px;">
                    <h1 style="color: #6366f1; margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.025em;">Aaptatt Private Limited</h1>
                    <p style="margin: 4px 0 0 0; color: #64748b; font-size: 14px; font-weight: 500;">Secure Document Portal</p>
                </div>
                
                <p style="font-size: 16px; margin-bottom: 20px;">Dear recipient,</p>
                
                <p style="font-size: 16px; margin-bottom: 30px;">
                    You have been invited to review and electronically sign a document from Aaptatt Private Limited. This request is secure and requires your immediate attention.
                </p>
                
                <div style="text-align: center; margin: 40px 0;">
                    <a href="{sign_link}" style="display: inline-block; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: #ffffff; padding: 16px 36px; text-decoration: none; border-radius: 12px; font-weight: 700; font-size: 16px; box-shadow: 0 10px 15px -3px rgba(99, 102, 241, 0.4);">
                        Access and Sign Document
                    </a>
                </div>
                
                <p style="font-size: 14px; color: #64748b; margin-top: 30px;">
                    For security, if the button above does not work, please copy and paste the link below into your web browser:
                    <br>
                    <a href="{sign_link}" style="color: #6366f1; text-decoration: underline; word-break: break-all;">{sign_link}</a>
                </p>
                
                <div style="margin-top: 50px; padding-top: 30px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8;">
                    <div style="margin-bottom: 10px;">
                        <strong>Aaptatt Private Limited</strong><br>
                        2nd Floor, Plot #4, Minarch Tower, Sector 44<br>
                        Gurugram, Haryana - 122003
                    </div>
                    <p style="margin: 0;">This is an automated notification from our secure signing system. Please do not reply to this email.</p>
                </div>
            </div>
            <div style="text-align: center; margin-top: 20px; font-size: 11px; color: #cbd5e1;">
                &copy; 2026 Aaptatt Private Limited. All rights reserved.
            </div>
        </div>
        """
        
        mail.send(msg)

        # Update status only if mail is sent successfully
        c.execute("UPDATE documents SET status='Sent' WHERE id=?", (doc_id,))
        conn.commit()
        conn.close()
        return redirect("/admin")

    except Exception as e:
        conn.close()
        return f"Failed to send email: {str(e)}", 500


@app.route("/uploads/<filename>")
def serve_pdf(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename))


# =======================
# SIGN DOCUMENT
# =======================

@app.route("/sign/<doc_id>", methods=["GET", "POST"])
def sign(doc_id):

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT filename, status FROM documents WHERE id=?", (doc_id,))
    doc = c.fetchone()

    if not doc:
        return "Invalid Link", 404

    filename, status = doc
    pdf_path = os.path.join(UPLOAD_FOLDER, filename)

    # Check if document is already signed
    if status == "Signed":
        # Get signing information
        c.execute("""
            SELECT signer_name, employee_id, signed_at, version
            FROM signed_documents
            WHERE document_id=?
            ORDER BY signed_at DESC
            LIMIT 1
        """, (doc_id,))
        sign_info = c.fetchone()
        conn.close()

        return render_template("sign.html",
                             doc_id=doc_id,
                             filename=filename,
                             already_signed=True,
                             sign_info=sign_info)

    if request.method == "POST":
        # Prevent signing if document is already signed
        if status == "Signed":
            return {"success": False, "error": "Document has already been signed"}, 403

        signature_data = request.form.get("signature")
        signer_name = request.form.get("signer_name")
        employee_id = request.form.get("employee_id") or "N/A"
        aadhar_number = request.form.get("aadhar_number") or "N/A"
        
        current_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        fields = load_fields(doc_id)

        original_pdf = PdfReader(pdf_path)
        writer = PdfWriter()

        # Only process signature image if data exists
        image = None
        if signature_data and "," in signature_data:
            signature_image = base64.b64decode(signature_data.split(",")[1])
            image_stream = io.BytesIO(signature_image)
            image = ImageReader(image_stream)

        for page_number in range(len(original_pdf.pages)):
            page = original_pdf.pages[page_number]

            packet = io.BytesIO()
            can = canvas.Canvas(packet)

            for field in fields:
                if field["page"] == page_number:
                    f_type = field.get("type", "signature")
                    
                    if f_type == "signature" and image:
                        # Signature image only
                        can.drawImage(
                            image,
                            field["x"],
                            field["y"],
                            width=field["width"],
                            height=field["height"],
                            mask="auto"
                        )
                    
                    elif f_type == "name":
                        can.setFont("Helvetica", 11)
                        # Center text vertically in the box (roughly 1/3 from bottom for baseline)
                        can.drawString(field["x"] + 5, field["y"] + (field["height"] / 2) - 4, signer_name)
                    
                    elif f_type == "aadhar":
                        can.setFont("Helvetica", 11)
                        can.drawString(field["x"] + 5, field["y"] + (field["height"] / 2) - 4, aadhar_number)
                    
                    elif f_type == "date":
                        can.setFont("Helvetica", 11)
                        can.drawString(field["x"] + 5, field["y"] + (field["height"] / 2) - 4, current_time)

            can.save()
            packet.seek(0)

            overlay = PdfReader(packet)
            if len(overlay.pages) > 0:
                page.merge_page(overlay.pages[0])

            writer.add_page(page)

        output = io.BytesIO()
        writer.write(output)
        output.seek(0)

        signed_bytes = output.getvalue()
        signed_hash = hashlib.sha256(signed_bytes).hexdigest()

        c.execute("""
            SELECT MAX(version) FROM signed_documents
            WHERE document_id=? AND employee_id=?
        """, (doc_id, employee_id))

        result = c.fetchone()[0]
        version = 1 if result is None else result + 1

        # Sanitize employee_id for filename (replace invalid characters)
        safe_employee_id = employee_id.replace("/", "-").replace("\\", "-").replace(" ", "_")
        enterprise_filename = f"{doc_id}_{safe_employee_id}_v{version}.pdf"
        enterprise_path = os.path.join(SIGNED_FOLDER, enterprise_filename)

        with open(enterprise_path, "wb") as f:
            f.write(signed_bytes)

        c.execute("""
            INSERT INTO signed_documents
            (document_id, employee_id, signer_name, version,
             signed_file, signed_hash, file_path, signed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            doc_id,
            employee_id,
            signer_name,
            version,
            signed_bytes,
            signed_hash,
            enterprise_filename,
            datetime.now().isoformat()
        ))

        c.execute("UPDATE documents SET status='Signed' WHERE id=?", (doc_id,))

        c.execute("""
            INSERT INTO audit_logs (document_id, employee_id, action, timestamp)
            VALUES (?, ?, ?, ?)
        """, (
            doc_id,
            employee_id,
            f"Signed Version {version}",
            datetime.now().isoformat()
        ))

        conn.commit()

        # Get the record ID of the signed document
        record_id = c.lastrowid

        conn.close()

        return {
            "success": True,
            "record_id": record_id,
            "version": version,
            "signer_name": signer_name
        }

    # Load signature fields to display on the PDF
    fields = load_fields(doc_id)

    conn.close()
    return render_template("sign.html",
                         doc_id=doc_id,
                         filename=filename,
                         fields=fields,
                         already_signed=False)


@app.route("/download-signed/<int:record_id>")
def download_signed_public(record_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT file_path, signer_name, version FROM signed_documents WHERE id=?", (record_id,))
    record = c.fetchone()
    conn.close()

    if not record or not record[0]:
        return "File not found", 404

    file_path = os.path.join(SIGNED_FOLDER, record[0])

    if not os.path.exists(file_path):
        return "File missing on server", 404

    download_name = f"signed_{record[1].replace(' ', '_')}_v{record[2]}.pdf"
    return send_file(file_path, as_attachment=True, download_name=download_name)


@app.route("/setup-hr")
def setup_hr():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    allowed = [
        "divyanshpandiit@gmail.com"
    ]

    for email in allowed:
        try:
            c.execute("INSERT INTO hr_allowed_emails (email) VALUES (?)", (email,))
        except:
            pass

    conn.commit()
    conn.close()

    return "HR emails added"
# =======================
# VIEW SIGNED RECORDS
# =======================

@app.route("/admin/signed")
def view_signed():

    if not session.get("hr_logged_in"):
        return redirect("/hr-login")

    search = request.args.get("search")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    if search:
        c.execute("""
            SELECT sd.id, sd.document_id, sd.employee_id, sd.signer_name, sd.version, sd.signed_at, d.email
            FROM signed_documents sd
            LEFT JOIN documents d ON sd.document_id = d.id
            WHERE sd.employee_id LIKE ?
               OR sd.signer_name LIKE ?
               OR d.email LIKE ?
            ORDER BY sd.signed_at DESC
        """, (f"%{search}%", f"%{search}%", f"%{search}%"))
    else:
        c.execute("""
            SELECT sd.id, sd.document_id, sd.employee_id, sd.signer_name, sd.version, sd.signed_at, d.email
            FROM signed_documents sd
            LEFT JOIN documents d ON sd.document_id = d.id
            ORDER BY sd.signed_at DESC
            LIMIT 10
        """)

    records = c.fetchall()
    conn.close()

    return render_template("signed_list.html", records=records)

@app.route("/admin/download/<int:record_id>")
def download_signed(record_id):

    if not session.get("hr_logged_in"):
        return redirect("/hr-login")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT file_path FROM signed_documents WHERE id=?", (record_id,))
    record = c.fetchone()
    conn.close()

    if not record or not record[0]:
        return "File not found in database"

    file_path = os.path.join(SIGNED_FOLDER, record[0])

    if not os.path.exists(file_path):
        return "File missing on server"

    return send_file(file_path, as_attachment=True)


# =======================
# VERIFY
# =======================

@app.route("/admin/verify/<doc_id>")
def verify(doc_id):
    if not session.get("hr_logged_in"):
        return redirect("/hr-login")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT filename, integrity_hash, email, created_at, status FROM documents WHERE id=?", (doc_id,))
    record = c.fetchone()
    conn.close()

    if not record:
        return "Document not found", 404

    filename, original_hash, email, created_at, status = record
    path = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(path):
        return "File not found on server", 404

    with open(path, "rb") as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()

    verified = current_hash == original_hash

    # Strip UUID from filename for display
    display_filename = filename.split('_', 1)[1] if '_' in filename else filename

    return render_template("verify.html",
                         verified=verified,
                         filename=display_filename,
                         email=email,
                         created_at=created_at,
                         status=status,
                         original_hash=original_hash,
                         current_hash=current_hash)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)