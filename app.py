import os
import sqlite3
import hashlib
import subprocess
import ast
from flask import Flask, request, jsonify

app = Flask(__name__)

# FIX 1: Secrets loaded from environment variables
DB_PASSWORD = os.getenv("DB_PASSWORD")

# FIX 2: Parameterized query prevents SQL Injection (CWE-89)
@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)

# FIX 3: subprocess list execution avoids shell injection
@app.route("/ping")
def ping():
    ip = request.args.get("ip", "127.0.0.1")
    subprocess.run(["ping", "-c", "1", ip], check=False)
    return jsonify({"status": "Ping executed"})

# FIX 4: jsonify safely handles output without manual HTML concatenation (XSS safe)
@app.route("/hello")
def hello():
    name = request.args.get("name", "Guest")
    return jsonify({"message": f"Hello {name}"})

# FIX 5: ast.literal_eval avoids eval(), SHA-256 replaces MD5, jsonify returns safe output
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1")
    result = ast.literal_eval(expr)
    strong_hash = hashlib.sha256(b"sensitive_data").hexdigest()
    return jsonify({"result": result, "hash": strong_hash})

if __name__ == "__main__":
    app.run(debug=False)
