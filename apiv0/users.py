from flask import Blueprint, request
from flask import current_app as meower

bp = Blueprint("users_blueprint", __name__)

@bp.route("/<username>", methods=["GET"])
def get_profile(username):
    return meower.resp(100, meower.get_user(username=username, abort_on_fail=True).public())

@bp.route("/<username>/posts", methods=["GET"])
def search_user_posts(username):
    # Authorize user
    meower.require_auth("header", ["oauth"], scopes=[], abort_on_none=False)

    # Get user data
    user = meower.get_user(username=username, abort_on_fail=True)

    # Check if requesting user can view this user's posts
    if user.data["privacy"]["private"] and ((request.user is None) or ((user.id != request.user.id) and (user.id not in request.user.data["relations"]["following"]))):
        return meower.resp(105, msg="You do not have permission to view this user's posts")

    # Get posts
    posts = meower.search_items("posts", {"user": user.id})

    # Convert into public post objects
    for i in range(len(posts)):
        posts[i] = meower.Post(meower, posts[i]).public((request.user.id if (request.user is not None) else None))

    # Return payload
    return meower.resp(100, {"posts": posts})

@bp.route("/<username>/report", methods=["POST"])
def report_user(username):
    # Check for required data
    meower.check_for_json([{"i": "reason", "t": str, "l_min": 0, "l_max": 500}])

    # Get user data
    user = meower.get_user(username=username, abort_on_fail=True)

    # Add report
    report_status = meower.db.reports.find_one({"content_type": "user", "content_id": user.id, "open": True})
    if report_status is None:
        meower.db.reports.insert_one({
            "_id": meower.uid(),
            "content_type": "user",
            "content_id": user.id,
            "reports": [{"user": request.user.id, "reason": request.json["reason"]}],
            "open": True,
            "created": meower.time()
        })
    elif request.user._id not in report_status["users"]:
        meower.db.reports.update_one({"_id": report_status["_id"]}, {"$push": {"reports": {"user": request.user.id, "reason": request.json["reason"]}}})

    # Return payload
    return meower.resp(100)