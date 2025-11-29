from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, db
import os, json, re
from datetime import datetime, timezone
import secrets
import string
import hmac
import hashlib
import time
import jwt

app = Flask(__name__)

service_account_key = os.environ["FIREBASE_SERVICE_ACCOUNT_KEY"]
database_url = os.environ["FIREBASE_RTDB_URL"]

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ISSUER = "https://afterduskgame.online"

cred_dict = json.loads(service_account_key)
cred = credentials.Certificate(cred_dict)

firebase_admin.initialize_app(cred, {
    "databaseURL": database_url
})

hmac_key = bytes.fromhex(os.environ["HMAC_KEY"])

def generate_default_password(length=64):
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def get_next_uid(transaction):
    if transaction is None:
        return 10000001
    return int(transaction) + 1

def issue_access_token_hs256(uid, client_id, expires_in=1296000, scope=None):
    now = int(time.time())
    jti = secrets.token_hex(16)
    payload = {
        "iss": JWT_ISSUER,
        "sub": str(uid),
        "aud": str(client_id),
        "iat": now,
        "exp": now + expires_in,
        "scope": scope or ["get_user_info"],
        "platform": 4,
        "jti": jti
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    open_id = jwt.encode({"uid": str(uid), "type": "openid"}, JWT_SECRET, algorithm="HS256")
    return token, open_id, jti

@app.route("/oauth/guest:register", methods=["POST"])
def create_uid():
    ua = request.headers.get("User-Agent")
    auth = request.headers.get("Authorization", "")
    content_type = request.headers.get("Content-Type", "")
    accept_enc = request.headers.get("Accept-Encoding", "")

    if not ua:
        return jsonify({"error": "Missing User-Agent"}), 400
    if not auth.startswith("Signature "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 400
    if not content_type.lower().startswith("application/x-www-form-urlencoded"):
        return jsonify({"error": "Content-Type must be application/x-www-form-urlencoded"}), 400
    if "gzip" not in accept_enc.lower():
        return jsonify({"error": "Accept-Encoding must include gzip"}), 400

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


def make_token_hex(nbytes=32):
    return secrets.token_hex(nbytes)

@app.route("/oauth/guest/token:grant", methods=["POST"])
def grant_token():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"code": 2, "message": "Invalid JSON body"}), 400

    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    client_type = data.get("client_type")
    password = data.get("password")
    response_type = data.get("response_type")
    uid = data.get("uid")

    if client_id is None or client_secret is None or uid is None or password is None:
        return jsonify({"code": 3, "message": "Missing required fields!"}), 400

    try:
        client_id = int(client_id)
        uid = int(uid)
    except Exception:
        return jsonify({"code": 4, "message": "client_id and uid must be integers"}), 400

    if client_id != 100067:
        return jsonify({"code": 5, "message": "Invalid client_id"}), 403

    if client_secret != os.environ["CLIENT_SECRET"]:
        return jsonify({"code": 6, "message": "Invalid client_secret"}), 403
    
    if response_type != "token":
        return jsonify({"code": 9, "message": "Invalid response_type"}), 400

    user_ref = db.reference(f"guest/{uid}")
    user = user_ref.get()
    if not user:
        return jsonify({"code": 7, "message": "User not found"}), 404

    stored_password = user.get("password")
    if stored_password is None or stored_password != password:
        return jsonify({"code": 8, "message": "Invalid uid or password"}), 403

    now = int(time.time())
    expires_in = 1296000
    refresh_token = make_token_hex(32)

    scope = ["get_user_info", "get_friends", "payment", "send_request"]
    access_token, open_id, jti = issue_access_token_hs256(uid, client_id, expires_in, scope=scope)

    access_token = access_token.encode().hex()
    open_id = open_id.encode().hex()

    create_time = now
    expiry_time = now + expires_in
    refresh_expiry_time = now + (expires_in * 2)

    data_resp = {
        "refresh_expiry_time": refresh_expiry_time,
        "expiry_time": expiry_time,
        "uid": uid,
        "open_id": open_id,
        "access_token": access_token,
        "main_active_platform": 4,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "platform": 4,
        "create_time": create_time,
        "scope": scope,
        "refresh_token": refresh_token
    }

    tokens_ref = db.reference(f"guest/{uid}/tokens")
    tokens_ref.set({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "open_id": open_id,
        "create_time": create_time,
        "expiry_time": expiry_time,
        "refresh_expiry_time": refresh_expiry_time,
        "client_id": client_id,
        "client_type": client_type,
        "scope": scope,
        "jti": jti
    })

    return jsonify({"code": 0, "data": data_resp}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)