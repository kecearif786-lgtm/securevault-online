import os
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from pymysql.cursors import DictCursor
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "CHANGE-ME-before-deploy"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
)

def db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "securevault"),
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=True,
    )

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Silakan login terlebih dahulu.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self';"
    return response

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 30 or not username.replace("_", "").isalnum():
            flash("Username 3–30 karakter; gunakan huruf, angka, atau underscore.", "danger")
            return render_template("register.html")
        if len(password) < 10:
            flash("Password minimal 10 karakter.", "danger")
            return render_template("register.html")
        try:
            with db() as conn:
                with conn.cursor() as cur:
                    cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                                (username, generate_password_hash(password)))
            flash("Akun berhasil dibuat. Silakan login.", "success")
            return redirect(url_for("login"))
        except pymysql.err.IntegrityError:
            flash("Username sudah digunakan.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, password_hash FROM users WHERE username=%s", (username,))
                user = cur.fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Username atau password tidak sesuai.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Kamu sudah logout.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM messages WHERE recipient_id=%s", (uid,))
            inbox_count = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM messages WHERE sender_id=%s", (uid,))
            sent_count = cur.fetchone()["n"]
            cur.execute("""SELECT m.id, m.subject, m.created_at, u.username AS sender
                           FROM messages m JOIN users u ON u.id=m.sender_id
                           WHERE m.recipient_id=%s ORDER BY m.created_at DESC LIMIT 5""", (uid,))
            latest = cur.fetchall()
    return render_template("dashboard.html", inbox_count=inbox_count, sent_count=sent_count, latest=latest)

@app.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    if request.method == "POST":
        recipient = request.form.get("recipient", "").strip()
        subject = request.form.get("subject", "").strip()[:120]
        ciphertext = request.form.get("ciphertext", "").strip()
        salt = request.form.get("salt", "").strip()
        iv = request.form.get("iv", "").strip()
        signature = request.form.get("signature", "").strip()
        pubkey = request.form.get("pubkey", "").strip()
        if not all([recipient, subject, ciphertext, salt, iv, signature, pubkey]):
            flash("Data pesan belum lengkap. Pastikan enkripsi dilakukan sebelum mengirim.", "danger")
            return redirect(url_for("compose"))
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE username=%s", (recipient,))
                target = cur.fetchone()
                if not target:
                    flash("Username penerima tidak ditemukan.", "danger")
                    return redirect(url_for("compose"))
                if target["id"] == session["user_id"]:
                    flash("Pilih penerima selain akun sendiri.", "warning")
                    return redirect(url_for("compose"))
                cur.execute("""INSERT INTO messages
                    (sender_id, recipient_id, subject, ciphertext, salt, iv, signature, pubkey)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (session["user_id"], target["id"], subject or "(Tanpa subjek)",
                     ciphertext, salt, iv, signature, pubkey))
        flash("Pesan terenkripsi berhasil dikirim.", "success")
        return redirect(url_for("sent"))
    return render_template("compose.html")

@app.route("/inbox")
@login_required
def inbox():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT m.id,m.subject,m.created_at,u.username AS sender
                           FROM messages m JOIN users u ON u.id=m.sender_id
                           WHERE m.recipient_id=%s ORDER BY m.created_at DESC""", (session["user_id"],))
            messages = cur.fetchall()
    return render_template("message_list.html", messages=messages, title="Kotak Masuk", kind="inbox")

@app.route("/sent")
@login_required
def sent():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT m.id,m.subject,m.created_at,u.username AS recipient
                           FROM messages m JOIN users u ON u.id=m.recipient_id
                           WHERE m.sender_id=%s ORDER BY m.created_at DESC""", (session["user_id"],))
            messages = cur.fetchall()
    return render_template("message_list.html", messages=messages, title="Pesan Terkirim", kind="sent")

@app.route("/message/<int:message_id>")
@login_required
def view_message(message_id):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT m.*, s.username AS sender, r.username AS recipient
                           FROM messages m JOIN users s ON s.id=m.sender_id
                           JOIN users r ON r.id=m.recipient_id
                           WHERE m.id=%s AND (m.sender_id=%s OR m.recipient_id=%s)""",
                        (message_id, session["user_id"], session["user_id"]))
            message = cur.fetchone()
    if not message:
        abort(404)
    return render_template("view_message.html", message=message)

@app.errorhandler(404)
def not_found(_):
    return render_template("base.html", page_error="Pesan atau halaman tidak ditemukan."), 404

if __name__ == "__main__":
    # Untuk pengembangan lokal saja. Gunakan server WSGI + HTTPS saat deployment.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
