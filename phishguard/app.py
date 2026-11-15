"""PhishGuard API.  Run: python app.py  ->  http://localhost:5000"""
from flask import Flask, jsonify, request, send_from_directory
from detector import analyze

app = Flask(__name__, static_folder="static", static_url_path="")

@app.get("/")
def index():
    return send_from_directory("static", "index.html")

@app.post("/api/check")
def check():
    url = (request.get_json(silent=True) or {}).get("url", "")
    if not url.strip() or len(url) > 2048:
        return jsonify(error="Paste a link to check (up to 2048 characters)."), 400
    try:
        return jsonify(analyze(url))     # the link is analysed, never visited
    except ValueError as e:
        return jsonify(error=str(e)), 400

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
