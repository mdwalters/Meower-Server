from flask import Blueprint, request, send_file
from flask import current_app as meower
import os
import requests
from jinja2 import Template
from threading import Thread
from hashlib import sha1
from passlib.hash import bcrypt

general = Blueprint("general_blueprint", __name__)

@general.before_app_request
def middleware():
    # Check for trailing backslashes in the URI
    if request.path.endswith("/"):
        request.path = request.path[:-1]

    # Make sure request method is upper case
    request.method = str(request.method).upper()

    # Extract the user's Cloudflare IP address from the request
    if "Cf-Connecting-Ip" in request.headers:
        request.remote_addr = request.headers["Cf-Connecting-Ip"]

    # Hash IP
    request.remote_addr = sha1(str(request.remote_addr).encode()).hexdigest()

    # Check if IP is banned
    if (request.remote_addr in meower.ip_banlist) and (not request.path.startswith("/admin")):
        return meower.resp(119)

    # Attempt to authorize the user
    if ("Authorization" in request.headers) and (len(str(request.headers.get("Authorization"))) <= 136):
        request.session = meower.Session(meower, str(request.headers.get("Authorization")).replace("Bearer ", "").strip())
        if request.session.authed:
            request.user = request.session.user
        else:
            request.user = None

@general.route("/", methods=["GET"])
def index():
    return meower.resp(100, msg="Welcome to the Meower API!")

@general.route("/status", methods=["GET"])
def get_status():
    data = meower.db.config.find_one({"_id": "supported_versions"})
    return meower.resp(100, {"isRepairMode": meower.repairMode, "scratchDeprecated": meower.scratchDeprecated, "supported": {"0": (0 in data["apis"])}, "supported_clients": data["clients"]})

@general.route('/favicon.ico', methods=['GET']) # Favicon, my ass. We need no favicon for an API.
def favicon_my_ass():
    return meower.resp(0)