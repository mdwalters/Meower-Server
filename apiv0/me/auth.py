from flask import Blueprint, request
from flask import current_app as meower
from passlib.hash import bcrypt
import pyotp

bp = Blueprint("foundation_auth", __name__)

def gen_session(userid):
    # Create session UID and get current time
    session_id = meower.uid()
    cur_time = meower.time()

    # Add session data to database
    session_data = {
        "_id": session_id,
        "t": "foundation",
        "v": 1,
        "u": userid,
        "ip": request.remote_addr,
        "ua": request.headers.get("User-Agent"),
        "app": None,
        "scopes": None,
        "access_expires": (cur_time + 259200000),
        "refresh_expires": (cur_time + 7776000000)
    }
    meower.db.sessions.insert_one(session_data)

    # Create and sign JWT token
    access_token, refresh_token = meower.gen_jwt_session(session_id, "foundation", 1)

    # Return signed JWT token
    return access_token, refresh_token, session_data["access_expires"], session_data["refresh_expires"]

@bp.route("/register", methods=["POST"])
def create_account():
    # Check for IP block
    if meower.db.netlog.find_one({"_id": request.remote_addr, "$or": [{"blocked": True}, {"creation_blocked": True}]}) is not None:
        return meower.resp(119, msg="Account creation is blocked on your IP")

    # Check for required data
    meower.check_for_json([{"i": "username", "t": str, "l_min": 1, "l_max": 20}, {"i": "password", "t": str, "l_max": 255}, {"i": "child", "t": bool}, {"i": "captcha", "t": str, "l_min": 1, "l_max": 1024}])

    # Extract username and password for simplicity
    username = request.json["username"].strip()
    password = request.json["password"].strip()
    child = request.json["child"]
    captcha = request.json["captcha"].strip()

    # Check if username is allowed
    if meower.check_username(username):
        return meower.resp(101, msg="Username not allowed")

    # Check captcha
    #if not meower.check_captcha(captcha):
        #return meower.resp(403, msg="Invalid captcha")

    # Create user
    userdata = meower, meower.create_user(username, password, child=child)
    if userdata is None:
        return meower.resp(15) # Username already exists

    # Create session
    access_token, refresh_token, access_expires, refresh_expires = gen_session(userdata["_id"])

    # Return session
    return meower.resp(100, {"access_token": access_token, "refresh_token": refresh_token, "access_expires": access_expires, "refresh_expires": refresh_expires})

@bp.route("/login/<username>", methods=["GET"])
def login_begin(username):
    return meower.resp(100, meower.get_user(username=username, abort_on_fail=True).pre_login())

@bp.route("/login/<username>/password", methods=["POST"])
def login_password(username):
    # Get user
    user = meower.get_user(username=username, abort_on_fail=True)

    # Get password
    stored_pswd = user.data["security"]["password"]
    meower.check_for_json([{"i": "password", "t": str, "l_min": 1, "l_max": 128}])
    password = request.json["password"].strip()

    # Check if user has had too many failed attempts
    meower.check_ratelimit("password", user.id)

    # Check if password is correct
    if stored_pswd is None:
        # Password is not a valid auth method
        return meower.resp(11, msg="Incorrect password")
    else:
        # Verify bcrypt password
        if not bcrypt.verify(password, stored_pswd):
            meower.ratelimit("password", user.id, burst=5, seconds=60)
            return meower.resp(11, msg="Incorrect password")

    # Check TOTP 2FA
    if user.data["security"]["totp"] is not None:
        # Generate token
        token = meower.gen_jwt_standalone("totp", user.id, {}, 300000)

        # Return token
        return meower.resp(16, {"access_token": token, "refresh_token": None, "access_expires": (meower.time() + 300000), "refresh_expires": None}, force_success=True)
    else:
        # Create session
        access_token, refresh_token, access_expires, refresh_expires = gen_session(user.id)

        # Return session
        return meower.resp(100, {"access_token": access_token, "refresh_token": refresh_token, "access_expires": access_expires, "refresh_expires": refresh_expires})

""" Not implemented stuff
@bp.route("/login/<username>/webauthn", methods=["POST"])
def login_webauthn(username):
    pass
"""

@bp.route("/verify/totp", methods=["POST"])
def complete_totp():
    # Check for auth
    meower.require_auth("header", "totp", standalone=True, allow_bots=False, allow_banned=True, allow_unapproved=True)

    # Get code
    meower.check_for_json([{"i": "code", "t": str, "l_min": 1, "l_max": 8}])
    code = request.json["code"].strip()
    totp_config = request.user.data["security"]["totp"]

    # Check if user has had too many failed attempts
    meower.check_ratelimit("totp", request.user.id)

    # Check if code is correct
    if totp_config is None:
        # TOTP is not enabled
        return meower.resp(11, msg="Invalid code")
    else:
        # Verify TOTP code
        if not (pyotp.TOTP(totp_config["secret"]).verify(code) or (code in totp_config["recovery"])):
            meower.ratelimit("totp", request.user.id, burst=5, seconds=60)
            return meower.resp(11, msg="Invalid code")
        elif code in totp_config["recovery"]:
            # Remove code from recovery codes
            meower.db.users.update_one({"_id": request.user.id}, {"$pull": {"security.totp.recovery": code}})

    # Block standalone JWT
    meower.db.blocked_jwts.insert_one({"_id": request.session["uid"], "added_at": meower.time()})

    # Create session
    access_token, refresh_token, access_expires, refresh_expires = gen_session(request.user.id)

    # Return session
    return meower.resp(100, {"access_token": access_token, "refresh_token": refresh_token, "access_expires": access_expires, "refresh_expires": refresh_expires})

@bp.route("/reset/password/<username>", methods=["POST"])
def reset_password(username):
    # Get user data
    user = meower.get_user(username=username, abort_on_fail=True)

    # Check if user has attempted too many times
    meower.check_ratelimit("reset-password", user.id)
    meower.ratelimit("reset-password", user.id, burst=1, seconds=300)

    # Attempt to send email
    if user.data["security"]["email"] is not None:
        # Decrypt email
        email = meower.decrypt(user.id, user.data["security"]["email"])

        # Generate token
        token = meower.gen_jwt_standalone("reset_pswd", user.id, {}, 600000)

        # Send email
        meower.send_email(email, "confirmations/reset_password", {"username": user.data["username"], "subject": "Reset your password", "token": token})

    # Return response
    return meower.resp(100)