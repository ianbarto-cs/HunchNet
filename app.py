import sqlite3
import uvicorn
import os

def init_db():
    os.makedirs("app/database", exist_ok=True)
    conn = sqlite3.connect("app/database/app.db")
    with open("db/schema.sql") as f:
        conn.executescript(f.read())
    conn.close()

init_db()

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000)
