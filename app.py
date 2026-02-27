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
import os
from werkzeug.utils import secure_filename

load_dotenv()
app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")
HR_USERNAME = os.getenv("HR_USERNAME")
HR_PASSWORD = os.getenv("HR_PASSWORD")
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
        # ✅ Clean filename (removes &, spaces, etc.)
        original_name = secure_filename(file.filename)

        # ✅ Add UUID to avoid duplicates
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
    c.execute("UPDATE documents SET status='Sent' WHERE id=?", (doc_id,))
    conn.commit()
    conn.close()
    return redirect("/admin")


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

        if not signature_data or not signer_name:
            return "Missing required data", 400

        fields = load_fields(doc_id)

        signature_image = base64.b64decode(signature_data.split(",")[1])
        original_pdf = PdfReader(pdf_path)
        writer = PdfWriter()

        image_stream = io.BytesIO(signature_image)
        image = ImageReader(image_stream)

        for page_number in range(len(original_pdf.pages)):
            page = original_pdf.pages[page_number]

            packet = io.BytesIO()
            can = canvas.Canvas(packet)

            for field in fields:
                if field["page"] == page_number:
                    can.drawImage(
                        image,
                        field["x"],
                        field["y"],
                        width=field["width"],
                        height=field["height"],
                        mask="auto"
                    )

                    can.drawString(field["x"], field["y"] - 15,
                                   f"Signed by: {signer_name}")
                    can.drawString(field["x"], field["y"] - 30,
                                   f"Employee ID: {employee_id}")
                    can.drawString(field["x"], field["y"] - 45,
                                   datetime.now().strftime("%d-%m-%Y"))

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