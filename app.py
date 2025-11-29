from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, db
import os, json, re
from datetime import datetime, timezone
import secrets
import string
import hmac
import hashlib

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

service_account_key = os.environ["FIREBASE_SERVICE_ACCOUNT_KEY"]
database_url = os.environ["FIREBASE_RTDB_URL"]

cred_dict = json.loads(service_account_key)
cred = credentials.Certificate(cred_dict)

firebase_admin.initialize_app(cred, {
    "databaseURL": database_url
})

hmac_key = bytes.fromhex(os.environ.get("HMAC_KEY"))

def generate_default_password(length=64):
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def get_next_uid(transaction):
    if transaction is None:
        return 10000001
    return int(transaction) + 1

@app.route("/oauth/guest/register", methods=["POST"])
def create_uid():
    ua = request.headers.get("User-Agent")
    auth = request.headers.get("Authorization", "")
    content_type = request.headers.get("Content-Type", "")
    accept_enc = request.headers.get("Accept-Encoding", "")
    connection = request.headers.get("Connection", "")

    if not ua:
        return jsonify({"error": "Missing User-Agent"}), 400
    if not auth.startswith("Signature "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 400
    if not content_type.lower().startswith("application/x-www-form-urlencoded"):
        return jsonify({"error": "Content-Type must be application/x-www-form-urlencoded"}), 400
    if "gzip" not in accept_enc.lower():
        return jsonify({"error": "Accept-Encoding must include gzip"}), 400
    if connection.lower() != "keep-alive":
        return jsonify({"error": "Connection must be Keep-Alive"}), 400

    body_bytes = request.get_data(cache=True)
    expected_sig = hmac.new(hmac_key, body_bytes, hashlib.sha256).hexdigest()
    provided_sig = auth.split(" ", 1)[1].strip()

    if not hmac.compare_digest(expected_sig, provided_sig):
        return jsonify({"error": "Invalid signature"}), 403

    password = request.form.get("password")
    client_type = request.form.get("client_type")
    source = request.form.get("source")
    app_id = request.form.get("app_id")

    if not password:
        password = generate_default_password()
        custom_password = False
    else:
        custom_password = True

    if not isinstance(password, str) or not re.compile(r"^[A-Za-z0-9_]+$").fullmatch(password):
        return jsonify({"error": "Password may contain A-Z, a-z, 0-9, and _ only."}), 400

    counter_ref = db.reference("uid_counter")
    try:
        next_uid = counter_ref.transaction(get_next_uid)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    uid_ref = db.reference(f"guest/{next_uid}")
    uid_ref.set({
        "password": password,
        "client_type": client_type,
        "source": source,
        "app_id": app_id,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "custom_password": custom_password,
        "user_agent": ua
    })

    resp = {"uid": next_uid}
    if custom_password:
        resp["password"] = password

    return jsonify(resp), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)