from http import client
from flask import Blueprint, request
from flask import current_app as meower

bp = Blueprint("oauth_apps", __name__)

@bp.route("/apps", methods=["GET", "POST", "PATCH", "DELETE"])
def manage_oauth_apps():
    # Check whether the client is authenticated
    meower.require_auth([5], scope="foundation:oauth:apps")

    if request.method == "GET": # Get all OAuth apps
        apps = meower.db.oauth.find({"owner": request.user._id}).sort("name", pymongo.ASCENDING)
        return meower.resp(200, {"apps": list(apps)})
    elif request.method == "POST": # Create new OAuth app
        # Check for required data
        meower.check_for_json([{"i": "name", "t": str, "l_min": 1, "l_max": 20}])

        # Extract app name for simplicity
        name = request.json["name"].strip()

        # Check if user has too many apps
        apps_count = meower.db.oauth.count_documents({"owner": request.user._id})
        if apps_count >= 50:
            return meower.resp({"type": "tooManyApps"}, 403, error=True)

        # Craete app data
        app_data = {
            "_id": str(uuid4()),
            "owner": request.user._id,
            "name": name,
            "description": "",
            "first_party": False,
            "bans": [],
            "allowed_redirects": [],
            "secret": secrets.token_urlsafe(64),
            "created": meower.time()
        }

        # Add app data to database
        meower.db.oauth.insert_one(app_data)

        # Return app data to user
        return meower.resp(200, app_data)

@bp.route("/apps/<app_id>", methods=["GET", "PATCH", "DELETE"])
def manage_oauth_app(app_id):
    # Check whether the client is authenticated
    meower.require_auth([5], scope="foundation:oauth:apps")

    # Check for bad syntax
    if len(app_id) > 32:
        return meower.resp(413)

    # Get app data
    app_data = meower.db.oauth.find_one({"_id": app_id})
    if (app_data is None) or (app_data["owner"] != request.user._id):
        return meower.resp({"type": "notFound", "message": "Requested OAuth app was not found"}, 404, error=True)

    # Check for required data
    if request.method == "GET": # Return app data
        return meower.resp(200, app_data)
    elif request.method == "PATCH": # Update app data
        # Update owner
        if ("owner" in request.json) and (len(request.json["owner"]) < 32):
            userdata = meower.db.users.find_one({"_id": request.json["owner"]})
            if userdata is None:
                return meower.resp({"type": "userDoesNotExist"}, 400, error=True)
            elif userdata["_id"] == request.user._id:
                return meower.resp({"type": "cannotChangeOwnerToSelf", "message": "You cannot change the owner to yourself"}, 400, error=True)
            else:
                app_data["owner"] = request.json["owner"]
                meower.db.oauth.update_one({"_id": app_id}, {"$set": {"owner": request.json["owner"]}})

        # Update name
        if ("name" in request.json) and (len(request.json["name"]) < 20):
            app_data["name"] = request.json["name"]
            meower.db.oauth.update_one({"_id": app_id}, {"$set": {"name": request.json["name"]}})

        # Update description
        if ("description" in request.json) and (len(request.json["description"]) < 200):
            app_data["description"] = request.json["description"]
            meower.db.oauth.update_one({"_id": app_id}, {"$set": {"description": request.json["description"]}})

        # Add bans
        if ("add_bans" in request.json) and (type(request.json["add_bans"]) == list):
            for user in request.json["add_bans"]:
                userdata = meower.db.users.find_one({"_id": user})
                if (userdata is None) and (user not in app_data["bans"]):
                    app_data["bans"].append(user)
            meower.db.oauth.update_one({"_id": app_id}, {"$set": {"bans": app_data["bans"]}})
        
        # Remove bans
        if ("remove_bans" in request.json) and (type(request.json["remove_bans"]) == list):
            for user in request.json["remove_bans"]:
                if user in app_data["bans"]:
                    app_data["bans"].remove(user)
            meower.db.oauth.update_one({"_id": app_id}, {"$set": {"bans": app_data["bans"]}})

        # Add bans
        if ("add_redirects" in request.json) and (type(request.json["add_redirects"]) == list):
            for user in request.json["add_redirects"]:
                if user not in app_data["allowed_redirects"]:
                    app_data["allowed_redirects"].append(user)
            meower.db.oauth.update_one({"_id": app_id}, {"$set": {"allowed_redirects": app_data["allowed_redirects"]}})
        
        # Remove bans
        if ("remove_redirects" in request.json) and (type(request.json["remove_redirects"]) == list):
            for user in request.json["remove_redirects"]:
                if user in app_data["allowed_redirects"]:
                    app_data["allowed_redirects"].remove(user)
            meower.db.oauth.update_one({"_id": app_id}, {"$set": {"allowed_redirects": app_data["allowed_redirects"]}})

        # Refresh secret
        if ("refresh_secret" in request.json) and (request.json["refresh_secret"] == True):
            app_data["secret"] = secrets.token_urlsafe(64)
            meower.db.oauth.update_one({"_id": app_id}, {"$set": {"secret": app_data["secret"]}})

        # Return new app data
        return meower.resp(200, app_data)
    elif request.method == "DELETE": # Delete app
        meower.db.oauth.delete_one({"_id": app_id})
        return meower.resp("empty")