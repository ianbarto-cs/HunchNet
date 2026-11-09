from fastapi import FastAPI, HTTPException, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from cryptography.hazmat.primitives.asymmetric import ec
import sqlite3
import bcrypt
import uuid
import secrets

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

DATABASE_PATH = "app/database/app.db"

def get_login_page():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HunchNet - Login</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="login-container">
        <h1>HunchNet</h1>
        <form id="login-form" method="post" action="/login">
            <div class="form-group">
                <label for="username">UserID</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <p class="register-link">Don't have an account? <a href="/register">Register</a></p>
    </div>
</body>
</html>
"""

def get_register_page():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="login-container">
        <h1>HunchNet - Register</h1>
        <form id="register-form" method="post" action="/register">
            <div class="form-group">
                <label for="display_name">Display Name</label>
                <input type="text" id="display_name" name="display_name" required>
            </div>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Register</button>
        </form>
        <p class="register-link">Already have an account? <a href="/">Login</a></p>
    </div>
</body>
</html>
"""

def get_dashboard_page():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HunchNet</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="dashboard-wrapper">
        <div class="sidebar">
            <div class="sidebar-header">
                <h2>Messages</h2>
                <a class="sidebar-new-message" href="#">+</a>
            </div>
            <ul class="contact-list">
               #This is where contacts will go eventually.
            </ul>
            <a class="sidebar-logout" href="/logout">Logout</a>
        </div>
        <div class="chat-area">
            <div class="chat-messages"></div>
            <form class="chat-input-area" method="post" action="/send_message">
                <input type="text" placeholder="Message...">
                <button>Send</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def read_root():
    return get_login_page()

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT ac.password_hash, u.id FROM auth_credentials ac JOIN users u ON ac.user_id = u.id WHERE u.username = ?",
        (username,)
    )
    result = cursor.fetchone()

    if not result:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_hex(32)
    cursor.execute(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now', '+7 days'))",
        (str(uuid.uuid4()), result[1], token)
    )
    conn.commit()
    conn.close()

    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie("session_token", token, httponly=True)
    return response

@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), display_name: str = Form(...)):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    
    cursor.execute("SELECT id FROM users WHERE display_name = ?", (display_name,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Display name already exists")

    user_id = str(uuid.uuid4())
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    time = datetime.datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO users (id, username, display_name, created_at) VALUES (?, ?, ?, ?)",
        (user_id, username, display_name, time)
    )
    cursor.execute(
        "INSERT INTO auth_credentials (id, user_id, password_hash) VALUES (?, ?, ?)",
        (str(uuid.uuid4()), user_id, password_hash)
    )
    conn.commit()
    conn.close()

    return RedirectResponse(url="/", status_code=302)

@app.get("/register", response_class=HTMLResponse)
def register_page():
    return get_register_page()

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(session_token: str = Cookie(default=None)):
    if not session_token:
        return RedirectResponse(url="/", status_code=302)

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM sessions WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > datetime('now')",
        (session_token,)
    )
    result = cursor.fetchone()
    conn.close()

    if not result:
        return RedirectResponse(url="/", status_code=302)

    return get_dashboard_page()

@app.get("/send_message")
def send_message(session_token: str = Cookie(default=None)):
    if not session_token:
        return RedirectResponse(url="/", status_code=302)

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM sessions WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > datetime('now')",
        (session_token,)
    )
    result = cursor.fetchone()
    conn.close()

    if not result:
        return RedirectResponse(url="/", status_code=302)


    

@app.get("/logout")
def logout(session_token: str = Cookie(default=None)):
    if session_token:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE sessions SET revoked_at = datetime('now') WHERE token_hash = ?",
            (session_token,)
        )
        conn.commit()
        conn.close()

    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("session_token")
    return response
