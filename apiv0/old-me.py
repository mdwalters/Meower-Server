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

me = Blueprint("me_blueprint", __name__)

@me.route("/", methods=["GET", "DELETE"])
def current_session():
    # Check whether the client is authenticated
    meower.require_auth([3, 5])

    if request.method == "GET":
        # Get session data from database
        session = request.session.json.copy()
        session["refresh_token"] = None
        session["previous_refresh_tokens"] = None

        # Get user data
        user = meower.User(meower, user_id=session["user"])

        # Return session data
        return meower.resp(200, {"session": session, "user": user.client, "foundation_session": (session["type"] == 3), "oauth_session": (session["type"] == 5)})
    elif request.method == "DELETE":
        # Delete session
        request.session.delete()
        return meower.resp("empty")

@me.route("/email-action", methods=["GET", "POST"])
def email_action():
    # Check for required data
    meower.check_for_params(["token"])

    # Extract token for simplicity
    token = request.args["token"]

    # Get session
    session = meower.db.email_sessions.find_one({"token": token, "expires": {"$gt": meower.time()}})

    # Check if session exists
    if session is None:
        return meower.resp(11)

    # Get session action
    if request.method == "GET":
        return meower.resp(100, {"id": session["_id"], "user": meower.get_user(userid=session["user"], abort_on_fail=False), "action": session["action"], "expires": session["expires"]})
    elif request.method == "POST":
        if session["action"] == "verify-email":
            # Get user data
            userdata = meower.db.users.find_one({"_id": session["user"]})

            # Check if user exists
            if userdata is None:
                return meower.resp(401)

            # Set email
            meower.db.users.update_one({"_id": session["user"]}, {"$set": {"security.email": session["email"]}})

            # Make user verified
            if userdata["state"] == 0:
                meower.db.users.update_one({"_id": session["user"]}, {"$set": {"state": 1}})

            # Delete session
            meower.db.sessions.delete_one({"_id": session["_id"]})

            return meower.resp(0)
        elif session["action"] == "revert-email":
            # Set old email
            meower.db.users.update_one({"_id": session["user"], "security.email": session["email"]})

            return meower.resp(0)
        elif session["action"] == "reset-password":
            # Get password
            meower.check_for_json([{"i": "password", "t": str, "l_min": 1, "l_max": 128}])
            password = request.json["password"].strip()

            # Set new password
            meower.db.users.update_one({"_id": session["user"], "security.password": bcrypt.hash(password)})

            return meower.resp(0)
        elif session["action"] == "download-data":
            # Check if data package exists
            if not ("{0}.zip".format(session["user"]) in os.listdir("apiv0/data_exports")):
                meower.db.sessions.delete_one({"_id": session["_id"]})
                return meower.resp(401)

            # Return data package
            return send_file("apiv0/data_exports/{0}.zip".format(session["user"]), as_attachment=True)

@me.route("/link/scratch/<link_session>", methods=["GET"])
def scratch_link_callback(link_session):
    # Check for required data
    meower.check_for_params(["privateCode"])

    # Extract code for simplicity
    code = request.args["privateCode"]

    # Get and delete session
    session = meower.db.link_sessions.find_one({"token": link_session, "expires": {"$gt": meower.time()}})
    meower.db.link_sessions.delete_one({"token": link_session})

    # Check if session exists
    if session is None:
        return meower.resp(11)

    # Get user
    user = meower.get_user(userid=session["user"], abort_on_fail=True)
    social_links = user.data["profile"]["social_links"]

    # Check OAuth
    api_resp = requests.post("https://auth.itinerary.eu.org/api/auth/verifyToken?privateCode={0}".format(code)).json()
    if api_resp["valid"]:
        data = {"provider": "scratch", "user_id": None, "username": api_resp["username"]}
        if data not in social_links:
            social_links.append(data)
            meower.db.users.update_one({"_id": user.id}, {"$set": {"profile.social_links": social_links}})
        return meower.resp(100, msg="Successfully linked account!")
    else:
        return meower.resp(104, msg="Failed to link account.")