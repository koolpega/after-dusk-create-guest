from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, db
import os, json, re
from datetime import datetime, timezone
import secrets
import string

app = Flask(__name__)

service_account_key = os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY")
database_url = os.environ.get("FIREBASE_RTDB_URL")

cred_dict = json.loads(service_account_key)
cred = credentials.Certificate(cred_dict)

firebase_admin.initialize_app(cred, {
    "databaseURL": database_url
})

def generate_default_password(length=64):
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def get_next_uid(transaction):
    if transaction is None:
        return 10000001
    return int(transaction) + 1

@app.route("/oauth/guest/register", methods=["POST"])
def create_uid():
    data = request.get_json(silent=True) or {}

    if "password" not in data or not data["password"]:
        password = generate_default_password()
        custom_password = True
    else:
        password = data["password"]
        custom_password = False

    if not isinstance(password, str) or not re.compile(r"^[A-Za-z0-9_]+$").fullmatch(password):
        return jsonify({"error": "Password may contain A-Z, a-z, 0-9, and _ only."}), 400

    counter_ref = db.reference("uid_counter")

    try:
        next_uid = counter_ref.transaction(get_next_uid)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    user_ref = db.reference(f"guest/{next_uid}")
    user_ref.set({
        "password": password,
        "created_at": datetime.now(timezone.utc).isoformat() + "Z",
        "custom_password": custom_password
    })

    resp = {"uid": next_uid}
    if custom_password:
        resp["password"] = password

    return jsonify(resp), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)