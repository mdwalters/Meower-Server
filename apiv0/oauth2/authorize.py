from http import client
from flask import Blueprint, request
from flask import current_app as meower

bp = Blueprint("oauth_authorize", __name__)

def gen_session(userid, app, scopes):
    # Create session UID and get current time
    session_id = meower.uid()
    cur_time = meower.time()

    # Add session data to database
    session_data = {
        "_id": session_id,
        "t": "oauth",
        "v": 1,
        "u": userid,
        "ip": None,
        "ua": None,
        "app": app,
        "scopes": scopes,
        "access_expires": (cur_time + 259200000),
        "refresh_expires": (cur_time + 7776000000)
    }
    meower.db.sessions.insert_one(session_data)

    # Create and sign JWT token
    access_token, refresh_token = meower.gen_jwt_session(session_id, "oauth", 1)

    # Return signed JWT token
    return access_token, refresh_token, session_data["access_expires"], session_data["refresh_expires"]

@bp.route("/app/<client_id>", methods=["GET", "POST"])
def authorize_app(client_id):
    # Check whether the client is authenticated
    meower.require_auth("header", "foundation", allow_bots=False)

    # Check for required data
    meower.check_for_json([{"i": "scopes", "t": list, "l_max": 1000}, {"i": "redirect_uri", "t": str, "l_max": 1000}])
 
    # Extract scopes and redirect URI for simplicity
    scopes = request.json["scopes"]
    redirect_uri = request.json["redirect_uri"].strip()

    # Get app data
    app_data = meower.db.oauth.find_one({"_id": client_id})
    if app_data is None:
        return meower.resp(103)

    if request.method == "GET":
        # Check if the OAuth app has been previously authorized with same scopes
        already_authorized = ((app_data["_id"] in list(request.user.data["authorized_oauth"].keys())) and (set(request.user.data["authorized_oauth"][app_data["_id"]]) == set(scopes)))

        # Get owner of app
        owner = meower.get_user(userid=app_data["owner"]).public()

        # Return app data
        return meower.resp(100, {"client_id": app_data["_id"], "name": app_data["name"], "description": app_data["description"], "icon": app_data["icon"], "owner": owner, "first_party": app_data["first_party"], "scopes": scopes, "redirect_allowed": (("*" in app_data["allowed_redirects"]) or (redirect_uri in app_data["allowed_redirects"])), "authorized": already_authorized})
    elif request.method == "POST":
        # Add to authorized apps
        request.user.data["authorized_oauth"][app_data["_id"]] = scopes
        meower.db.users.update_one({"_id": request.user.id}, {"$set": {"authorized_oauth": request.user.data["authorized_oauth"]}})

        # Generate an exchange token
        exchange_token = meower.gen_jwt_standalone("exchange", request.user.id, {"a": app_data["_id"], "s": scopes}, 300000)

        # Return exchange token
        return meower.resp(100, {"exchange_token": exchange_token, "exchange_expires": (meower.time() + 300000)})

@bp.route("/token", methods=["POST"])
def exchange_oauth_code():
    # Check for auth
    meower.require_auth("body", "exchange", standalone=True, allow_bots=False)
 
    # Extract app ID, client secret and scopes for simplicity
    meower.check_for_json([{"i": "client_id", "t": str, "l_max": 32}, {"i": "client_secret", "t": str, "l_max": 50}])
    client_id = request.json["app"].strip()
    client_secret = request.json["secret"].strip()
    scopes = request.session["scopes"]

    # Check if client ID matches app the token was made for
    if request.session["a"] != client_id:
        return meower.resp(11, msg="Invalid authorization token", abort=True)

    # Get app data
    app_data = meower.db.oauth.find_one({"_id": client_id})
    if app_data is None:
        return meower.resp(101, msg="OAuth client not found", abort=True)

    # Check if client secret is correct
    if client_secret != app_data["secret"]:
        return meower.resp(11, msg="Invalid OAuth client secret", abort=True)

    # Delete exchange session
    meower.db.sessions.delete_one({"_id": request.session["_id"]})

    # Create OAuth session
    access_token, refresh_token, access_expires, refresh_expires = gen_session(request.user.id, client_id, scopes)

    # Return session
    return meower.resp(100, {"access_token": access_token, "refresh_token": refresh_token, "access_expires": access_expires, "refresh_expires": refresh_expires, "scopes": scopes})

@bp.route("/refresh", methods=["POST"])
def refresh_session():
    # Check for auth
    meower.require_auth("header", "refresh", allow_bots=False)

    # Get current time
    cur_time = meower.time()

    # Increment version and expiration
    request.session["v"] += 1
    request.session["access_expires"] = (cur_time + 259200000)
    request.session["refresh_expires"] = (cur_time + 7776000000)
    meower.db.sessions.update_one({"_id": request.session["uid"]}, {"$set": {"v": request.session["v"], "access_expires": request.session["access_expires"], "refresh_expires": request.session["refresh_expires"]}})

    # Create new JWT tokens
    access_token, refresh_token = meower.gen_jwt_session(request.session["uid"], "oauth", request.session["v"])

    # Return session
    return meower.resp(100, {"access_token": access_token, "refresh_token": refresh_token, "access_expires": request.session["access_expires"], "refresh_expires": request.session["refresh_expires"], "scopes": request.session["scopes"]})