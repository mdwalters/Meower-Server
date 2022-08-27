from flask import Blueprint, request
from flask import current_app as meower
from passlib.hash import bcrypt
import pyotp
import secrets
import string

bp = Blueprint("foundation_auth", __name__)

@bp.route("/register", methods=["POST"])
def create_account():
    # Check for IP block
    if meower.db.netlog.find_one({"_id": request.remote_addr, "$or": [{"blocked": True}, {"creation_blocked": True}]}) is not None:
        return meower.resp(119, msg="Account creation is blocked on your IP")

    # Check for required data
    meower.check_for_json([{"i": "username", "t": str, "l_min": 1, "l_max": 20}, {"i": "password", "t": str, "l_max": 256}, {"i": "child", "t": bool}, {"i": "captcha", "t": str, "l_min": 1, "l_max": 1024}])

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
    userdata = meower.create_user(username, password, child=child)
    if userdata is None:
        return meower.resp(15) # Username already exists

    # Return session
    return meower.resp(100)

@bp.route("/login/<username>", methods=["GET"])
def login_begin(username):
    return meower.resp(100, meower.get_user(username=username, abort_on_fail=True).pre_login())

@bp.route("/login/<username>/password", methods=["POST"])
def login_password(username):
    # Get user data
    userdata = meower.get_user(username=username, abort_on_fail=True).data

    # Get password
    stored_pswd = userdata["security"]["password"]
    meower.check_for_json([{"i": "password", "t": str, "l_min": 1, "l_max": 128}])
    password = request.json["password"].strip()

    # Check if user has had too many failed attempts
    meower.check_ratelimit("password", userdata["_id"])

    # Check if password is correct
    if stored_pswd is None:
        # Password is not a valid auth method
        return meower.resp(11, msg="Incorrect password")
    else:
        # Verify bcrypt password
        if not bcrypt.verify(password, stored_pswd["hash"]):
            meower.ratelimit("password", userdata["_id"], burst=5, seconds=60)
            return meower.resp(11, msg="Incorrect password")

    # Check TOTP 2FA
    if userdata["security"]["totp"] is not None:
        meower.check_for_json([{"i": "totp", "t": str, "l_min": 6, "l_max": 10}])

        # Check if user has had too many failed attempts
        meower.check_ratelimit("totp", userdata["_id"])

        totp_code = request.json["totp"].replace("-", "")
        if (not pyotp.TOTP(userdata["security"]["totp"]["secret"]).verify(totp_code)) and (totp_code not in userdata["security"]["totp"]["recovery"]):
            meower.ratelimit("totp", userdata["_id"], burst=5, seconds=60)
            return meower.resp(401, msg="Invalid TOTP")
        elif totp_code in userdata["security"]["totp"]["recovery"]:
            userdata["security"]["totp"]["recovery"].remove(totp_code)
            meower.db.users.update_one({"_id": userdata["_id"]}, {"$set": {"security.totp.recovery": userdata["security"]["totp"]["recovery"]}})

    # Return response
    return meower.resp(200, meower.foundation_session(userdata["_id"], "your password"))

@bp.route("/login/<username>/webauthn", methods=["POST"])
def login_webauthn(username):
    return meower.resp(501)

@bp.route("/login/device", methods=["GET"])
def login_device():
    # Check whether the client is authenticated
    meower.require_auth([1])

    # Delete session
    request.session.delete()

    # Full account session
    return meower.resp(200, meower.foundation_session(request.user._id, "another device"))

@bp.route("/reset/password/<username>", methods=["POST"])
def reset_password(username):
    return meower.send_email("confirmations/reset_password", "tnix@meower.org", username, "Reset your password", {"username": username, "link": "https://meower.org/email?token={0}".format(meower.gen_jwt_standalone({"t": "reset_pswd", "u": username}, 600000)), "expiration": "10 minutes"})
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
        token = meower.gen_jwt_standalone({"t": "reset_pswd", "u": user.id}, 600000)

        # Send email
        meower.send_email(email, "confirmations/reset_password", {"username": user.data["username"], "subject": "Reset your password", "token": token})

    # Return response
    return meower.resp(100)