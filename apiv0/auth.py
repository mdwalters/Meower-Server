import re
from threading import Thread
from jinja2 import Template
from flask import Blueprint, request
from flask import current_app as meower
from passlib.hash import bcrypt
import pyotp
import secrets
import string
from uuid import uuid4
import string
import pymongo

app = Blueprint("foundation_auth", __name__)

@app.route("/register", methods=["POST"])
def create_account():
    # Check for account creation block
    if meower.db.netlog.find_one({"_id": request.remote_addr, "creation_blocked": True}) is not None:
        return meower.resp(119, msg="Account creation is blocked on your IP")

    # Check for required data
    meower.check_for_json([{"i": "username", "t": str, "l_min": 1, "l_max": 20}, {"i": "password", "t": str, "l_max": 256}, {"i": "child", "t": bool}, {"i": "captcha", "t": str, "l_min": 1, "l_max": 1024}])

    # Extract username and password for simplicity
    username = request.json["username"].strip()
    password = request.json["password"].strip()

    # Check for bad characters
    if meower.check_for_bad_chars_username(username):
        return meower.resp(400, msg="Username has an illegal character")

    # Check if the username is allowed
    for bad_username in meower.blocked_usernames:
        if bad_username.lower() in username.lower():
            return meower.resp(409, msg="Username already taken")

    # Check if account exists
    if meower.db.users.find_one({"lower_username": username.lower()}) is not None:
        return meower.resp(409, msg="Username already taken")

    # Check captcha
    #if not meower.check_captcha(request.json["captcha"]):
        #return meower.resp(403, msg="Invalid captcha")

    # Create userdata
    userdata = {
        "_id": meower.uid(),
        "username": username,
        "lower_username": username.lower(),
        "bot": False,
        "bot_owner": None,
        "last_ip": None,
        "created": int(meower.time()),
        "delete_after": None,
        "config": {
            "theme": "orange",
            "light": True,
            "sfx": True,
            "bgm": {
                "enabled": True,
                "data": None
            },
            "debug": False
        },
        "profile": {
            "pfp": "",
            "quote": "",
            "status": 1,
            "badges": [],
            "last_seen": int(meower.time())
        },
        "permissions": {
            "ban_status": None,
            "mod_lvl": 0
        },
        "authorized_oauth": {},
        "security": {
            "email": None,
            "password": bcrypt.hash(password),
            "webauthn": [],
            "totp": None
        },
        "privacy": {
            "private": False,
            "follow_requests": 1, # 0: Approval required, 1: Auto accept, 2: Auto deny
            "dm_requests": 0
        },
        "relations": {
            "following": [],
            "follow_requests": [],
            "blocked": []
        },
        "guardian": {
            "child": request.json["child"],
            "parent_approved": False,
            "linked_guardian": None,
            "account_disabled": False,
            "filter_level": 0,
            "user_whitelist": False,
            "community_whitelist": False,
            "groups_enabled": True,
            "encrypted_chats": True,
            "allowed_users": [],
            "blocked_users": [],
            "allowed_communities": [],
            "blocked_communities": [],
        }
    }
    meower.db.users.insert_one(userdata)

    # Return session
    return meower.resp(200, meower.foundation_session(userdata["_id"], "your password"))

@app.route("/login/<username>", methods=["GET"])
def login_begin(username):
    return meower.resp(100, meower.get_user(username=username, abort_on_fail=True).pre_login())

@app.route("/login/<username>/password", methods=["POST"])
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

@app.route("/login/<username>/webauthn", methods=["POST"])
def login_webauthn(username):
    return meower.resp(501)

@app.route("/login/device", methods=["GET"])
def login_device():
    # Check whether the client is authenticated
    meower.require_auth([1])

    # Delete session
    request.session.delete()

    # Full account session
    return meower.resp(200, meower.foundation_session(request.user._id, "another device"))

@app.route("/reset/password/<username>", methods=["POST"])
def reset_password(username):
    # Get user data
    user = meower.get_user(username=username, abort_on_fail=True)

    # Check if user has attempted too many times
    meower.check_ratelimit("reset-password", user.id)
    meower.ratelimit("reset-password", user.id, burst=1, seconds=300)

    # Attempt to send email
    if user.data["security"]["email"] is not None:
        # Decrypt email
        email = meower.decrypt(user.data["security"]["email"])

        # Generate email verification code
        code = str("".join(secrets.choice(string.ascii_letters + string.digits) for i in range(8))).upper()
        meower.email_session(user.id, user.data["security"]["email"], "reset-password")

        # Send email
        meower.send_email(email, "confirmations/login_code", {"username": user.data["username"], "subject": "Login verification code", "code": code})

    # Return response
    return meower.resp(100)