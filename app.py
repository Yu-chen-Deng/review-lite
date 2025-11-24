import os
import sqlite3
import csv
import io
import json
from flask import Flask, request, jsonify, session, send_from_directory, make_response
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random

# --- Configuration ---
app = Flask(__name__)
app.secret_key = "super_secret_key_for_demo_only"  # Change this for production
UPLOAD_FOLDER = "uploads"
DB_NAME = "review_system.db"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "docx", "xlsx", "pptx"}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# --- Database Initialization & Helpers ---


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    # Users Table
    c.execute(
        """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )"""
    )

    # Entities Table
    c.execute(
        """CREATE TABLE IF NOT EXISTS entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT
    )"""
    )

    # Attachments Table
    c.execute(
        """CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_id INTEGER,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        FOREIGN KEY(entity_id) REFERENCES entities(id)
    )"""
    )

    # Scores Table
    c.execute(
        """CREATE TABLE IF NOT EXISTS scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_id INTEGER,
        reviewer_id INTEGER,
        score_interview INTEGER,
        score_summary INTEGER,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(entity_id, reviewer_id)
    )"""
    )

    # System Settings Table
    c.execute(
        """CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )"""
    )
    # Default Settings
    defaults = {
        "show_scores_to_reviewer": "0",  # Allow reviewers to see others' scores
        "blind_review_mode": "0",  # Enable blind review (anonymous)
        "allow_score_interview": "1",  # Allow editing Interview score
        "allow_score_summary": "1",  # Allow editing Summary score
    }

    for key, val in defaults.items():
        c.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val)
        )

    # Default Admin (if not exists)
    try:
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin"), "admin"),
        )
    except sqlite3.IntegrityError:
        pass

    # Default Reviewers (Only added on first init for demo purposes)
    count = c.execute("SELECT count(*) FROM users WHERE role='reviewer'").fetchone()[0]
    if count == 0:
        reviewers = [("r1", "123"), ("r2", "123"), ("r3", "123")]
        for u in reviewers:
            try:
                c.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (u[0], generate_password_hash(u[1]), "reviewer"),
                )
            except:
                pass

    c.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
        ("show_scores_to_reviewer", "0"),
    )

    conn.commit()
    conn.close()


# Initialize Run
init_db()

# --- Backend Routes ---


@app.route("/")
def index():
    return HTML_TEMPLATE


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user["password"], password):
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        return jsonify(
            {"status": "success", "role": user["role"], "username": user["username"]}
        )

    return jsonify({"status": "error", "message": "Invalid username or password"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "success"})


@app.route("/api/check_auth", methods=["GET"])
def check_auth():
    if "user_id" in session:
        return jsonify(
            {
                "is_logged_in": True,
                "role": session["role"],
                "username": session["username"],
            }
        )
    return jsonify({"is_logged_in": False})


@app.route("/uploads/<path:filename>")
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# --- User Management API ---


@app.route("/api/users", methods=["GET"])
def get_users():
    if "user_id" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, role FROM users WHERE role = 'reviewer' ORDER BY username"
    ).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])


@app.route("/api/users", methods=["POST"])
def add_user():
    if "user_id" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Missing fields"}), 400

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), "reviewer"),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "User already exists"}), 400
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    if "user_id" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    conn = get_db()
    # Delete user and all their scores
    conn.execute("DELETE FROM scores WHERE reviewer_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


# --- Entities & Attachments API ---


@app.route("/api/entities", methods=["GET"])
def get_entities():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()

    # 1. Get system settings
    settings_rows = conn.execute("SELECT key, value FROM settings").fetchall()
    settings = {row["key"]: (row["value"] == "1") for row in settings_rows}

    entities_rows = conn.execute("SELECT * FROM entities ORDER BY id DESC").fetchall()

    # Get all attachments
    attachments_rows = conn.execute("SELECT * FROM attachments").fetchall()
    attachments_map = {}
    for att in attachments_rows:
        eid = att["entity_id"]
        if eid not in attachments_map:
            attachments_map[eid] = []
        attachments_map[eid].append(dict(att))

    # Get current user's scores
    my_scores = {}
    if session["role"] == "reviewer":
        rows = conn.execute(
            "SELECT entity_id, score_interview, score_summary FROM scores WHERE reviewer_id = ?",
            (session["user_id"],),
        ).fetchall()
        for r in rows:
            my_scores[r["entity_id"]] = {
                "interview": r["score_interview"],
                "summary": r["score_summary"],
            }

    # Get scoring status list (Map reviewer_id to username for better display)
    user_rows = conn.execute("SELECT id, username FROM users").fetchall()
    user_map = {u["id"]: u["username"] for u in user_rows}

    score_status = {}
    rows = conn.execute("SELECT entity_id, reviewer_id FROM scores").fetchall()
    for r in rows:
        if r["entity_id"] not in score_status:
            score_status[r["entity_id"]] = []
        uname = user_map.get(r["reviewer_id"], f"Unknown({r['reviewer_id']})")
        score_status[r["entity_id"]].append(uname)

    # Get all score details
    all_scores_detail = {}
    setting = conn.execute(
        "SELECT value FROM settings WHERE key='show_scores_to_reviewer'"
    ).fetchone()
    # Logic: Return details if admin, or if setting is enabled
    is_admin = session["role"] == "admin"
    show_scores = setting["value"] == "1"

    if is_admin or show_scores:
        rows = conn.execute("SELECT * FROM scores").fetchall()
        for r in rows:
            if r["entity_id"] not in all_scores_detail:
                all_scores_detail[r["entity_id"]] = []

            # Inject username into score object
            s_dict = dict(r)
            s_dict["reviewer_name"] = user_map.get(r["reviewer_id"], "Unknown")
            all_scores_detail[r["entity_id"]].append(s_dict)

    entities = []
    for e in entities_rows:
        ent = dict(e)
        ent["attachments"] = attachments_map.get(e["id"], [])
        ent["my_score"] = my_scores.get(e["id"], {})
        ent["reviewed_by"] = score_status.get(e["id"], [])
        ent["all_scores"] = all_scores_detail.get(e["id"], [])

        # --- Blind Review Mode Logic Start ---
        is_reviewer = session["role"] == "reviewer"
        is_blind_mode = settings.get("blind_review_mode", False)

        if is_reviewer and is_blind_mode:
            # Core trick: Use session["user_id"] as random seed
            # 1. Random: For Reviewer ID 1, order might be [3, 1, 2]
            # 2. Random: For Reviewer ID 2, order might be [2, 3, 1]
            # 3. Stable: Reviewer 1 always sees [3, 1, 2] on refresh
            random.seed(session["user_id"])
            random.shuffle(entities)
            # Reset random seed
            random.seed(None)

            # Mask Names
            ent["name"] = "Candidate"
            # ent["name"] = f"Candidate #{ent['id']:03d}"
            ent["description"] = "******** (Blind Mode: Information Hidden) ********"

            # Mask Attachment Names
            for att in ent["attachments"]:
                ext = att["filename"].split(".")[-1]
                att["filename"] = f"Anonymous_Doc.{ext}"
        # --- Blind Review Mode Logic End ---

        entities.append(ent)

    conn.close()
    return jsonify(entities)


@app.route("/api/entities", methods=["POST"])
def add_entity():
    if "user_id" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    name = request.form.get("name")
    desc = request.form.get("description")
    files = request.files.getlist("files")

    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO entities (name, description) VALUES (?, ?)", (name, desc)
    )
    entity_id = cursor.lastrowid

    for file in files:
        if file and file.filename:
            save_attachment(conn, entity_id, file)

    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/entities/<int:entity_id>/attachments", methods=["POST"])
def add_attachment_to_entity(entity_id):
    if "user_id" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    files = request.files.getlist("files")
    conn = get_db()
    for file in files:
        if file and file.filename:
            save_attachment(conn, entity_id, file)
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


def save_attachment(conn, entity_id, file):
    filename = secure_filename(file.filename)
    unique_filename = f"{entity_id}_{int(datetime.now().timestamp())}_{filename}"
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], unique_filename))
    filepath = f"/uploads/{unique_filename}"
    conn.execute(
        "INSERT INTO attachments (entity_id, filename, filepath) VALUES (?, ?, ?)",
        (entity_id, filename, filepath),
    )


@app.route("/api/attachments/<int:attachment_id>", methods=["DELETE"])
def delete_attachment(attachment_id):
    if "user_id" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    att = conn.execute(
        "SELECT filepath FROM attachments WHERE id = ?", (attachment_id,)
    ).fetchone()
    if att:
        # Delete file
        fname = att["filepath"].replace("/uploads/", "")
        full_path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
        if os.path.exists(full_path):
            try:
                os.remove(full_path)
            except:
                pass
        # Delete record
        conn.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
        conn.commit()

    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/entities/<int:entity_id>", methods=["DELETE"])
def delete_entity(entity_id):
    if "user_id" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()

    # Find and delete physical files
    attachments = conn.execute(
        "SELECT filepath FROM attachments WHERE entity_id = ?", (entity_id,)
    ).fetchall()
    for att in attachments:
        fname = att["filepath"].replace("/uploads/", "")
        full_path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
        if os.path.exists(full_path):
            try:
                os.remove(full_path)
            except:
                pass

    conn.execute("DELETE FROM attachments WHERE entity_id = ?", (entity_id,))
    conn.execute("DELETE FROM scores WHERE entity_id = ?", (entity_id,))
    conn.execute("DELETE FROM entities WHERE id = ?", (entity_id,))

    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/score", methods=["POST"])
def submit_score():
    if "user_id" not in session or session["role"] != "reviewer":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()

    # 1. Check if scoring is allowed
    settings_rows = conn.execute("SELECT key, value FROM settings").fetchall()
    settings = {row["key"]: (row["value"] == "1") for row in settings_rows}

    data = request.json
    entity_id = data.get("entity_id")

    # Get existing score (to update only allowed fields)
    current_score = conn.execute(
        "SELECT score_interview, score_summary FROM scores WHERE entity_id=? AND reviewer_id=?",
        (entity_id, session["user_id"]),
    ).fetchone()

    current_interview = current_score["score_interview"] if current_score else None
    current_summary = current_score["score_summary"] if current_score else None

    # New scores
    new_interview = data.get("score_interview")
    new_summary = data.get("score_summary")

    # Handle empty strings -> None
    new_interview = (
        int(new_interview)
        if new_interview is not None and new_interview != ""
        else None
    )
    new_summary = (
        int(new_summary) if new_summary is not None and new_summary != "" else None
    )

    # --- Locking Logic ---
    # If Interview score modification not allowed, force old score
    if not settings.get("allow_score_interview", True):
        final_interview = current_interview
    else:
        final_interview = new_interview

    # If Summary score modification not allowed, force old score
    if not settings.get("allow_score_summary", True):
        final_summary = current_summary
    else:
        final_summary = new_summary
    # ------------------

    conn.execute(
        """
        INSERT INTO scores (entity_id, reviewer_id, score_interview, score_summary)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(entity_id, reviewer_id) DO UPDATE SET
        score_interview=excluded.score_interview,
        score_summary=excluded.score_summary,
        updated_at=CURRENT_TIMESTAMP
    """,
        (entity_id, session["user_id"], final_interview, final_summary),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/settings", methods=["GET", "POST"])
def handle_settings():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    if request.method == "POST":
        # Only Admin can modify
        if session["role"] != "admin":
            conn.close()
            return jsonify({"error": "Unauthorized"}), 403

        data = request.json
        # Update allowed settings
        keys = [
            "show_scores_to_reviewer",
            "blind_review_mode",
            "allow_score_interview",
            "allow_score_summary",
        ]
        for k in keys:
            if k in data:
                val = "1" if data[k] is True else "0"
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (k, val),
                )

        conn.commit()
        conn.close()
        return jsonify({"status": "success"})

    else:
        # GET: All logged-in users get settings (frontend needs to gray out inputs)
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        settings = {row["key"]: (row["value"] == "1") for row in rows}
        conn.close()
        return jsonify(settings)


@app.route("/api/export_excel")
def export_excel():
    if "user_id" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db()
    entities = conn.execute("SELECT id, name FROM entities").fetchall()
    reviewers = conn.execute(
        "SELECT id, username FROM users WHERE role='reviewer' ORDER BY username"
    ).fetchall()
    scores = conn.execute("SELECT * FROM scores").fetchall()
    conn.close()

    score_map = {}
    for s in scores:
        if s["entity_id"] not in score_map:
            score_map[s["entity_id"]] = {}
        score_map[s["entity_id"]][s["reviewer_id"]] = {
            "interview": s["score_interview"],
            "summary": s["score_summary"],
        }

    output = io.BytesIO()
    # Changed encoding to utf-8-sig for better international Excel support
    wrapper = io.TextIOWrapper(
        output, encoding="utf-8-sig", errors="replace", newline=""
    )
    writer = csv.writer(wrapper)

    headers = ["ID", "Candidate"]
    for r in reviewers:
        headers.append(f"{r['username']}-Interview")
        headers.append(f"{r['username']}-Summary")
    writer.writerow(headers)

    for e in entities:
        row = [e["id"], e["name"]]
        e_scores = score_map.get(e["id"], {})
        for r in reviewers:
            r_score = e_scores.get(r["id"], {})
            row.append(r_score.get("interview", ""))
            row.append(r_score.get("summary", ""))
        writer.writerow(row)

    wrapper.flush()
    wrapper.detach()
    output.seek(0)

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=review_scores.csv"
    response.headers["Content-type"] = "text/csv; charset=utf-8-sig"
    return response


# --- Frontend Code ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Review Lite</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.4.2/mammoth.browser.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
    <style>
        [v-cloak] { display: none; }
        .docx-content { background: white; padding: 20px; overflow-y: auto; max-height: 100%; }
        .excel-table { width: 100%; border-collapse: collapse; }
        .excel-table td, .excel-table th { border: 1px solid #ccc; padding: 4px; font-size: 12px; }
        .line-clamp-2 {
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen font-sans">
    <div id="app" v-cloak>
        
        <div v-if="!isLoggedIn" class="flex items-center justify-center min-h-screen bg-gray-200">
            <div class="bg-white p-8 rounded-lg shadow-lg w-96">
                <h1 class="text-2xl font-bold mb-6 text-center text-blue-600">Review Lite Login</h1>
                <div class="mb-4">
                    <label class="block text-gray-700 text-sm font-bold mb-2">Account</label>
                    <input v-model="loginForm.username" class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="admin or r1">
                </div>
                <div class="mb-6">
                    <label class="block text-gray-700 text-sm font-bold mb-2">Password</label>
                    <input v-model="loginForm.password" type="password" @keyup.enter="handleLogin" class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="Default: admin or 123">
                </div>
                <button @click="handleLogin" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition">
                    Enter System
                </button>
                <p v-if="loginError" class="text-red-500 text-xs mt-3 text-center">{{ loginError }}</p>
            </div>
        </div>

        <div v-else>
            <nav class="bg-blue-700 text-white p-4 shadow-lg sticky top-0 z-40">
                <div class="container mx-auto flex justify-between items-center">
                    <div class="text-xl font-bold flex items-center gap-2">
                        <span>Review Lite</span>
                        <span class="text-xs bg-blue-800 px-2 py-0.5 rounded">{{ role === 'admin' ? 'Admin' : 'Reviewer' }}</span>
                    </div>
                    <div class="flex items-center space-x-4">
                        <span class="text-sm opacity-90">User: {{ username }}</span>
                        <button @click="logout" class="bg-red-500 hover:bg-red-600 px-3 py-1 rounded text-sm transition">Logout</button>
                    </div>
                </div>
            </nav>

            <div class="container mx-auto p-4 md:p-6">
                
                <div v-if="role === 'admin'" class="bg-white p-4 rounded-lg shadow mb-6 flex flex-col gap-4">
                    <div class="flex flex-wrap gap-6 border-b pb-4">
                        <label class="flex items-center cursor-pointer select-none">
                            <div class="relative">
                                <input type="checkbox" v-model="settings.blind_review_mode" @change="toggleSettings" class="sr-only">
                                <div class="w-10 h-5 bg-gray-300 rounded-full shadow-inner transition-colors" :class="{'bg-purple-500': settings.blind_review_mode}"></div>
                                <div class="absolute w-5 h-5 bg-white rounded-full shadow left-0 top-0 transition-transform" :class="{'translate-x-full': settings.blind_review_mode}"></div>
                            </div>
                            <div class="ml-2 text-gray-700 font-bold text-sm">👁️ Blind Review Mode</div>
                        </label>

                        <label class="flex items-center cursor-pointer select-none">
                            <div class="relative">
                                <input type="checkbox" v-model="settings.show_scores_to_reviewer" @change="toggleSettings" class="sr-only">
                                <div class="w-10 h-5 bg-gray-300 rounded-full shadow-inner transition-colors" :class="{'bg-blue-500': settings.show_scores_to_reviewer}"></div>
                                <div class="absolute w-5 h-5 bg-white rounded-full shadow left-0 top-0 transition-transform" :class="{'translate-x-full': settings.show_scores_to_reviewer}"></div>
                            </div>
                            <div class="ml-2 text-gray-700 font-medium text-sm">Show Scores to Reviewers</div>
                        </label>
                        
                        <div class="h-6 w-px bg-gray-300 mx-2"></div> <label class="flex items-center cursor-pointer select-none">
                            <input type="checkbox" v-model="settings.allow_score_interview" @change="toggleSettings" class="form-checkbox h-4 w-4 text-green-600 rounded">
                            <span class="ml-2 text-sm text-gray-700">Allow Interview Score</span>
                        </label>

                        <label class="flex items-center cursor-pointer select-none">
                            <input type="checkbox" v-model="settings.allow_score_summary" @change="toggleSettings" class="form-checkbox h-4 w-4 text-green-600 rounded">
                            <span class="ml-2 text-sm text-gray-700">Allow Summary Score</span>
                        </label>
                    </div>

                    <div class="flex justify-between items-center">
                        <button @click="showUserModal = true" class="text-blue-600 hover:text-blue-800 text-sm font-medium underline">
                            Manage Reviewers
                        </button>
                        <div class="flex gap-2">
                                <button @click="showAddModal = true" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded text-sm shadow transition">
                                + Add Entity
                            </button>
                            <a href="/api/export_excel" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded text-sm shadow transition flex items-center">
                                Export Excel
                            </a>
                        </div>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    <div v-for="entity in entities" :key="entity.id" class="bg-white rounded-lg shadow hover:shadow-xl transition duration-300 flex flex-col h-full border border-gray-100">
                        <div class="p-5 flex-1 flex flex-col">
                            <div class="flex justify-between items-start mb-2">
                                <h3 class="text-lg font-bold text-gray-800 truncate" :title="entity.name">{{ entity.name }}</h3>
                                <div class="flex items-center gap-2">
                                     <span v-if="role === 'reviewer'">
                                        <span v-if="hasScored(entity)" class="bg-green-100 text-green-700 text-xs px-2 py-0.5 rounded-full font-bold">Scored</span>
                                        <span v-else class="bg-yellow-100 text-yellow-700 text-xs px-2 py-0.5 rounded-full font-bold">Pending</span>
                                    </span>
                                    <button v-if="role === 'admin'" @click="deleteEntity(entity)" class="text-gray-400 hover:text-red-500 text-lg leading-none" title="Delete Entity">
                                        &times;
                                    </button>
                                </div>
                            </div>
                            
                            <p class="text-gray-600 text-sm mb-4 line-clamp-2" :title="entity.description">{{ entity.description }}</p>
                            
                            <div class="mt-auto bg-gray-50 rounded p-2 border border-dashed border-gray-300">
                                <div class="flex justify-between items-center mb-1">
                                    <span class="text-xs font-bold text-gray-500 uppercase">Attachments</span>
                                    <label v-if="role === 'admin'" class="cursor-pointer text-xs text-blue-600 hover:underline">
                                        +Add
                                        <input type="file" multiple class="hidden" @change="(e) => addAttachment(e, entity.id)">
                                    </label>
                                </div>
                                
                                <div v-if="entity.attachments && entity.attachments.length > 0" class="flex flex-wrap gap-2">
                                    <div v-for="att in entity.attachments" :key="att.id" class="group flex items-center bg-white border rounded px-2 py-1 shadow-sm max-w-full">
                                        <span class="text-xs text-blue-600 truncate max-w-[100px] cursor-pointer hover:underline" :title="att.filename" @click="previewFile(att)">
                                            {{ att.filename }}
                                        </span>
                                        <button v-if="role === 'admin'" @click.stop="deleteAttachment(att.id)" class="ml-1 text-gray-300 hover:text-red-500 font-bold leading-none hidden group-hover:block">&times;</button>
                                    </div>
                                </div>
                                <div v-else class="text-xs text-gray-400 text-center py-1">No attachments</div>
                            </div>
                        </div>

                        <div class="border-t bg-gray-50 p-4 rounded-b-lg">
                            
                            <div v-if="role === 'reviewer'" class="mb-3">
                                <div class="grid grid-cols-2 gap-2 mb-2">
                                    <div>
                                        <label class="text-xs text-gray-500 block">Interview</label>
                                        <input type="number" 
                                            v-model="entity.my_score.interview" 
                                            :disabled="!settings.allow_score_interview"
                                            :class="{'bg-gray-100 cursor-not-allowed': !settings.allow_score_interview}"
                                            class="w-full text-sm border rounded px-1 py-1 text-center transition-colors" 
                                            placeholder="-">
                                    </div>
                                    <div>
                                        <label class="text-xs text-gray-500 block">Summary</label>
                                        <input type="number" 
                                            v-model="entity.my_score.summary" 
                                            :disabled="!settings.allow_score_summary"
                                            :class="{'bg-gray-100 cursor-not-allowed': !settings.allow_score_summary}"
                                            class="w-full text-sm border rounded px-1 py-1 text-center transition-colors" 
                                            placeholder="-">
                                    </div>
                                </div>
                                <button v-if="settings.allow_score_interview || settings.allow_score_summary"
                                        @click="submitScore(entity)" 
                                        class="w-full bg-blue-600 hover:bg-blue-700 text-white text-xs py-1.5 rounded transition">
                                    Save Score
                                </button>
                                <div v-else class="text-xs text-red-500 text-center py-1 bg-red-50 rounded">
                                    Channel Closed
                                </div>
                            </div>

                            <div>
                                <div class="text-xs text-gray-500 mb-1 flex justify-between">
                                    <span>Reviewed by:</span>
                                    <span class="font-bold">{{ entity.reviewed_by.length }} Users</span>
                                </div>
                                
                                <div class="mt-1 text-gray-600">
                                    <span 
                                        v-for="(name, idx) in entity.reviewed_by" 
                                        :key="idx"
                                    >
                                        {{ name }}&nbsp;
                                    </span>
                                </div>
                                
                                <div v-if="entity.all_scores && entity.all_scores.length > 0" class="mt-2 max-h-32 overflow-y-auto custom-scrollbar">
                                    <table class="w-full text-xs text-left">
                                        <thead class="bg-gray-200 text-gray-600 sticky top-0">
                                            <tr>
                                                <th class="p-1 rounded-tl">User</th>
                                                <th class="p-1">Interview</th>
                                                <th class="p-1 rounded-tr">Summary</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr v-for="s in entity.all_scores" class="border-b last:border-0 border-gray-200">
                                                <td class="p-1 font-medium text-gray-700">{{ s.reviewer_name }}</td>
                                                <td class="p-1 text-blue-600">{{ s.score_interview || '-' }}</td>
                                                <td class="p-1 text-blue-600">{{ s.score_summary || '-' }}</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                                <div v-else-if="role === 'reviewer' && !settings.show_scores_to_reviewer" class="text-xs text-gray-400 italic text-center mt-2">
                                    Scores hidden
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div v-if="showAddModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                <div class="bg-white p-6 rounded-lg shadow-xl w-full max-w-md">
                    <h2 class="text-lg font-bold mb-4">Add Entity/Candidate</h2>
                    <div class="mb-3">
                        <label class="block text-sm mb-1">Name</label>
                        <input v-model="newEntity.name" class="w-full border p-2 rounded text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none">
                    </div>
                    <div class="mb-3">
                        <label class="block text-sm mb-1">Description</label>
                        <textarea v-model="newEntity.description" class="w-full border p-2 rounded text-sm h-24 focus:ring-2 focus:ring-blue-500 focus:outline-none"></textarea>
                    </div>
                    <div class="mb-4">
                        <label class="block text-sm mb-1">Initial Attachments</label>
                        <input type="file" ref="fileInput" multiple class="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100">
                    </div>
                    <div class="flex justify-end space-x-2">
                        <button @click="showAddModal = false" class="px-4 py-2 text-gray-600 text-sm hover:bg-gray-100 rounded">Cancel</button>
                        <button @click="createEntity" class="px-4 py-2 bg-blue-600 text-white rounded text-sm hover:bg-blue-700">Submit</button>
                    </div>
                </div>
            </div>

            <div v-if="showUserModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                <div class="bg-white p-6 rounded-lg shadow-xl w-full max-w-md">
                    <h2 class="text-lg font-bold mb-4">Manage Reviewer Accounts</h2>
                    
                    <div class="flex gap-2 mb-4 bg-gray-50 p-2 rounded">
                        <input v-model="newUser.username" placeholder="Username" class="border p-1 text-sm rounded flex-1">
                        <input v-model="newUser.password" placeholder="Password" class="border p-1 text-sm rounded flex-1">
                        <button @click="addUser" class="bg-green-500 text-white px-3 py-1 rounded text-sm hover:bg-green-600">Add</button>
                    </div>

                    <div class="max-h-60 overflow-y-auto border-t">
                        <table class="w-full text-sm text-left">
                            <thead class="bg-gray-100 text-gray-600">
                                <tr>
                                    <th class="p-2">Username</th>
                                    <th class="p-2 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="u in userList" :key="u.id" class="border-b">
                                    <td class="p-2">{{ u.username }}</td>
                                    <td class="p-2 text-right">
                                        <button @click="deleteUser(u)" class="text-red-500 hover:underline text-xs">Delete</button>
                                    </td>
                                </tr>
                                <tr v-if="userList.length === 0">
                                    <td colspan="2" class="p-4 text-center text-gray-400">No reviewers found</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="flex justify-end mt-4">
                         <button @click="showUserModal = false" class="px-4 py-2 bg-gray-200 text-gray-700 rounded text-sm hover:bg-gray-300">Close</button>
                    </div>
                </div>
            </div>

            <div v-if="preview.url" class="fixed inset-0 bg-black bg-opacity-90 flex items-center justify-center z-50 p-4">
                <div class="bg-white rounded-lg shadow-xl w-full max-w-6xl h-5/6 flex flex-col relative">
                    <div class="flex justify-between items-center p-3 border-b bg-gray-50 rounded-t-lg">
                        <h3 class="font-bold text-gray-700 truncate max-w-lg">{{ preview.filename }}</h3>
                        <div class="flex items-center space-x-3">
                            <button @click="closePreview" class="text-gray-500 hover:text-red-500 text-2xl font-bold leading-none">&times;</button>
                        </div>
                    </div>
                    <div class="flex-1 bg-gray-200 overflow-auto flex justify-center p-4 relative">
                        <div v-if="preview.loading" class="absolute inset-0 flex items-center justify-center bg-white bg-opacity-80 z-10">
                            <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                        </div>
                        <iframe v-if="preview.type === 'pdf'" :src="preview.url" class="w-full h-full shadow-lg bg-white"></iframe>
                        <img v-else-if="preview.type === 'image'" :src="preview.url" class="max-w-full max-h-full object-contain shadow-lg">
                        <div v-else-if="preview.type === 'html'" v-html="preview.htmlContent" class="docx-content shadow-lg w-full max-w-4xl h-fit min-h-full"></div>
                        <div v-else class="text-center mt-20">
                            <div class="text-6xl mb-4">📄</div>
                            <p class="text-gray-600 mb-2">Online preview not supported ({{preview.ext}})</p>
                            </div>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <script>
        const { createApp, ref, reactive, onMounted } = Vue;

        createApp({
            setup() {
                const isLoggedIn = ref(false);
                const role = ref('');
                const username = ref('');
                const loginForm = reactive({ username: '', password: '' });
                const loginError = ref('');
                
                const entities = ref([]);
                const settings = reactive({ 
                    show_scores_to_reviewer: false,
                    blind_review_mode: false,
                    allow_score_interview: true,
                    allow_score_summary: true
                });
                
                // Entity Modal
                const showAddModal = ref(false);
                const newEntity = reactive({ name: '', description: '' });
                const fileInput = ref(null);

                // User Management Modal
                const showUserModal = ref(false);
                const userList = ref([]);
                const newUser = reactive({ username: '', password: '' });

                // Preview
                const preview = reactive({ url: null, type: '', filename: '', ext: '', htmlContent: '', loading: false });

                onMounted(async () => {
                    const res = await fetch('/api/check_auth');
                    const data = await res.json();
                    if (data.is_logged_in) {
                        isLoggedIn.value = true;
                        role.value = data.role;
                        username.value = data.username;
                        loadData();
                        if (role.value === 'admin') loadUsers();
                    }
                });

                // Load Data
                const loadData = async () => {
                    // 1. Load entities
                    const entRes = await fetch('/api/entities');
                    entities.value = await entRes.json();
                    
                    // 2. Load settings (Everyone needs this)
                    const setRes = await fetch('/api/settings');
                    const setData = await setRes.json();
                    
                    settings.show_scores_to_reviewer = setData.show_scores_to_reviewer;
                    settings.blind_review_mode = setData.blind_review_mode;
                    settings.allow_score_interview = setData.allow_score_interview;
                    settings.allow_score_summary = setData.allow_score_summary;
                };

                // Toggle Settings
                const toggleSettings = async () => {
                    await fetch('/api/settings', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(settings)
                    });
                    loadData();
                };

                const loadUsers = async () => {
                    const res = await fetch('/api/users');
                    userList.value = await res.json();
                };

                const handleLogin = async () => {
                    const res = await fetch('/api/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(loginForm)
                    });
                    const data = await res.json();
                    if (data.status === 'success') {
                        isLoggedIn.value = true;
                        role.value = data.role;
                        username.value = data.username;
                        loginError.value = '';
                        loadData();
                        if (role.value === 'admin') loadUsers();
                    } else {
                        loginError.value = data.message;
                    }
                };

                const logout = async () => {
                    await fetch('/api/logout', { method: 'POST' });
                    window.location.reload();
                };

                // --- Entity Management ---
                const createEntity = async () => {
                    const formData = new FormData();
                    formData.append('name', newEntity.name);
                    formData.append('description', newEntity.description);
                    if (fileInput.value.files) {
                        for(let i=0; i < fileInput.value.files.length; i++){
                            formData.append('files', fileInput.value.files[i]);
                        }
                    }
                    await fetch('/api/entities', { method: 'POST', body: formData });
                    showAddModal.value = false;
                    newEntity.name = ''; newEntity.description = ''; fileInput.value.value = ''; 
                    loadData();
                };

                const deleteEntity = async (entity) => {
                    if(!confirm(`Are you sure you want to delete "${entity.name}"?`)) return;
                    await fetch(`/api/entities/${entity.id}`, { method: 'DELETE' });
                    loadData();
                };

                // --- Attachment Management ---
                const addAttachment = async (event, entityId) => {
                    const files = event.target.files;
                    if (!files.length) return;
                    
                    const formData = new FormData();
                    for(let i=0; i<files.length; i++) formData.append('files', files[i]);
                    
                    await fetch(`/api/entities/${entityId}/attachments`, { method: 'POST', body: formData });
                    loadData();
                };

                const deleteAttachment = async (attId) => {
                    if(!confirm('Delete this attachment?')) return;
                    await fetch(`/api/attachments/${attId}`, { method: 'DELETE' });
                    loadData();
                };

                // --- Reviewer Management ---
                const addUser = async () => {
                    if(!newUser.username || !newUser.password) return;
                    const res = await fetch('/api/users', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(newUser)
                    });
                    const data = await res.json();
                    if(data.error) alert(data.error);
                    else {
                        newUser.username = ''; newUser.password = '';
                        loadUsers();
                    }
                };

                const deleteUser = async (u) => {
                    if(!confirm(`Are you sure you want to delete reviewer ${u.username}? Their scoring records will also be deleted.`)) return;
                    await fetch(`/api/users/${u.id}`, { method: 'DELETE' });
                    loadUsers();
                    loadData(); // Re-fetch to update scores list
                };

                // --- Scoring & Settings ---
                const submitScore = async (entity) => {
                    await fetch('/api/score', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            entity_id: entity.id,
                            score_interview: entity.my_score.interview,
                            score_summary: entity.my_score.summary
                        })
                    });
                    loadData();
                };

                const hasScored = (entity) => {
                    const s = entity.my_score;
                    return (s.interview !== null && s.interview !== '') || (s.summary !== null && s.summary !== '');
                };

                // --- Preview ---
                const closePreview = () => { preview.url = null; };
                const previewFile = async (att) => {
                    const ext = att.filename.split('.').pop().toLowerCase();
                    preview.url = att.filepath;
                    preview.filename = att.filename;
                    preview.ext = ext;
                    preview.loading = true;
                    preview.htmlContent = '';
                    preview.type = '';

                    if (['pdf'].includes(ext)) preview.type = 'pdf';
                    else if (['png', 'jpg', 'jpeg', 'gif'].includes(ext)) preview.type = 'image';
                    else if (['docx'].includes(ext)) {
                        preview.type = 'html';
                        try {
                            const response = await fetch(att.filepath);
                            const ab = await response.arrayBuffer();
                            const res = await mammoth.convertToHtml({arrayBuffer: ab});
                            preview.htmlContent = res.value;
                        } catch (e) { preview.type = 'error'; }
                    } else if (['xlsx', 'xls'].includes(ext)) {
                        preview.type = 'html';
                        try {
                            const response = await fetch(att.filepath);
                            const ab = await response.arrayBuffer();
                            const workbook = XLSX.read(ab, {type: 'array'});
                            const html = XLSX.utils.sheet_to_html(workbook.Sheets[workbook.SheetNames[0]], { id: "excel-table" });
                            preview.htmlContent = html.replace('<table', '<table class="excel-table"');
                        } catch (e) { preview.type = 'error'; }
                    } else {
                        preview.type = 'unsupported';
                    }
                    preview.loading = false;
                };

                return {
                    isLoggedIn, role, username, loginForm, loginError,
                    entities, settings, handleLogin, logout,
                    showAddModal, newEntity, fileInput, createEntity, deleteEntity,
                    showUserModal, userList, newUser, addUser, deleteUser,
                    addAttachment, deleteAttachment,
                    submitScore, toggleSettings, hasScored,
                    preview, previewFile, closePreview
                };
            }
        }).mount('#app');
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True, port=5000)
