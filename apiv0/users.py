from flask import Blueprint, request
from flask import current_app as meower
import pymongo
import time

users = Blueprint("users_blueprint", __name__)

@users.route("/<username>", methods=["GET"])
def get_profile(username):
    return meower.resp(100, meower.get_user(username=username, abort_on_fail=True).public())

@users.route("/<username>/posts", methods=["GET"])
def search_user_posts(username):
    # Get user data
    user = meower.get_user(username=username, abort_on_fail=True)

    # Check if requesting user can view this user's posts
    if user.data["privacy"]["private"] and ((request.user is None) or (user.id not in request.user.data["relations"]["following"])):
        return meower.resp(105, msg="You do not have permission to view this user's posts")

    # Get page
    if not ("page" in request.args):
        page = 1
    else:
        page = int(request.args["page"])

    # Get posts
    posts = list(meower.db.posts.find({"user": user.id, "deleted": False}).skip((page-1)*25).limit(25).sort("time", pymongo.DESCENDING))

    # Convert user objects
    for i in range(len(posts)):
        posts[i]["user"] = user.public()

    # Return payload
    return meower.resp(100, {"posts": posts})

@users.route("/<username>/report", methods=["POST"])
def report_user(username):
    # Check for required data
    meower.check_for_json([{"i": "comment", "t": str, "l_min": 1, "l_max": 360}])

    # Get user data
    userdata = meower.db.users.find_one({"lower_username": username.lower()})
    if userdata is None:
        return meower.resp(404)

    # Add report
    report_status = meower.db.reports.find_one({"_id": userdata["_id"]})
    if report_status is None:
        report_status = {
            "_id": userdata["_id"],
            "type": 0,
            "users": [],
            "ips": [],
            "comments": [],
            "t": int(meower.time()),
            "review_status": 0
        }
        report_status["users"].append(request.user._id)
        report_status["comments"].append({"u": request.user._id, "t": int(meower.time()), "p": request.json["comment"]})
        report_status["ips"].append(request.remote_addr)
        meower.db.reports.insert_one(report_status)
    elif request.user._id not in report_status["users"]:
        report_status["users"].append(request.user._id)
        report_status["comments"].append({"u": request.user._id, "t": int(meower.time()), "p": request.json["comment"]})
        if (request.remote_addr not in report_status["ips"]) and (request.user.state >= 1):
            report_status["ips"].append(request.remote_addr)
        meower.db.reports.find_one_and_replace({"_id": userdata["_id"]}, report_status)

    # Return payload
    return meower.resp("empty")