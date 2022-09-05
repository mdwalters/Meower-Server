from flask import Blueprint, request
from flask import current_app as meower
import secrets

bp = Blueprint("oauth_apps", __name__)

@bp.route("/", methods=["GET", "POST", "PATCH", "DELETE"])
def manage_oauth_apps():
    # Check whether the client is authenticated
    meower.require_auth("header", ["oauth"], scopes=["oauth"])

    if request.method == "GET": # Get all OAuth apps
        apps = meower.search_items("oauth", {"owner": request.user.id})
        return meower.resp(200, {"apps": apps})
    elif request.method == "POST": # Create new OAuth app
        # Check for required data
        meower.check_for_json([{"i": "name", "t": str, "l_min": 1, "l_max": 20}])

        # Extract app name for simplicity
        name = request.json["name"].strip()

        # Craete app data
        app_data = {
            "_id": meower.uid(),
            "owner": request.user.id,
            "name": name,
            "description": "",
            "icon": None,
            "first_party": False,
            "allowed_redirects": [],
            "secret": secrets.token_urlsafe(32),
            "created": meower.time()
        }

        # Add app data to database
        meower.db.oauth.insert_one(app_data)

        # Return app data to user
        return meower.resp(100, app_data)

@bp.route("/<app_id>", methods=["GET", "PATCH", "DELETE"])
def manage_oauth_app(app_id):
    # Check whether the client is authenticated
    meower.require_auth("header", ["oauth"], scopes=["oauth"])

    # Get app data
    app_data = meower.db.oauth.find_one({"_id": app_id})
    if (app_data is None) or (app_data["owner"] != request.user.id):
        return meower.resp(103)

    # Check for required data
    if request.method == "GET": # Return app data
        return meower.resp(100, app_data)
    elif request.method == "PATCH": # Update app data
        # Update name
        if ("name" in request.json) and (len(request.json["name"]) < 20):
            app_data["name"] = request.json["name"]

        # Update description
        if ("description" in request.json) and (len(request.json["description"]) < 200):
            app_data["description"] = request.json["description"]

        # Update icon
        if ("icon" in request.json) and (len(request.json["icon"]) < 50):
            app_data["icon"] = request.json["icon"]

        # Add allowed redirects
        if ("add_redirect" in request.json) and (type(request.json["add_redirect"]) == str) and (request.json["add_redirect"] not in app_data["allowed_redirects"]):
            app_data["allowed_redirects"].append(request.json["add_redirect"])
        
        # Remove allowed redirects
        if ("remove_redirect" in request.json) and (type(request.json["remove_redirect"]) == str) and (request.json["remove_redirect"] in app_data["allowed_redirects"]):
            app_data["allowed_redirects"].remove(request.json["remove_redirect"])

        # Refresh secret
        if ("refresh_secret" in request.json) and (request.json["refresh_secret"] == True):
            app_data["secret"] = secrets.token_urlsafe(64)

        # Destroy all sessions
        if ("destroy_sessions" in request.json) and (request.json["destroy_sessions"] == True):
            meower.db.sessions.delete_many({"app": app_data["_id"]})

        # Update app data
        meower.db.oauth.update_one({"_id": app_data["_id"]}, {"$set": {"name": app_data["name"], "description": app_data["description"], "icon": app_data["icon"], "allowed_redirects": app_data["allowed_redirects"], "secret": app_data["secret"]}})

        # Return new app data
        return meower.resp(100, app_data)
    elif request.method == "DELETE": # Delete app
        meower.db.users.update_one({"oauth.authorized": {"$all": [app_data["_id"]]}}, {"oauth.authroized": {"$pull": app_data["_id"]}})
        meower.db.sessions.delete_many({"app": app_data["_id"]})
        meower.db.oauth.delete_one({"_id": app_id})
        return meower.resp(100)