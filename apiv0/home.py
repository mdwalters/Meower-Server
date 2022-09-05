from flask import Blueprint, request
from flask import current_app as meower

bp = Blueprint("home", __name__)

@bp.route("/", methods=["GET", "POST"])
def get_latest_posts():
    if request.method == "GET":
        # Check whether the user is authorized
        meower.require_auth("header", ["oauth"], scopes=[], abort_on_none=False)

        # Get posts
        posts = meower.search_items("posts", {"deleted": False}, project={"_id": 1, "author": 1, "nick": 1, "content": 1, "attatchment": 1, "likes": 1, "meows": 1, "created": 1})

        # Temporary user object getting
        print(posts)
        for i in range(len(posts)):
            posts[i]["author"] = meower.db.users.find_one({"_id": posts[i]["author"]}, projection={"_id": 1, "username": 1, "profile.pfp": 1})

        """
        # Convert into public post objects
        for i in range(len(posts)):
            posts[i] = meower.Post(meower, posts[i]).public((request.user.id if (request.user is not None) else None))
        """

        # Return payload
        return meower.resp(100, {"posts": posts})
    elif request.method == "POST":
        # Check whether the user is authorized
        meower.require_auth("header", ["oauth"], scopes=[])

        # Create post
        post = meower.create_home_post(request.user.id, request.json["content"], None)

        # Return payload
        return meower.resp(100, post.public(authed_user=request.user.id))

@bp.route("/personalized", methods=["GET"])
def get_personalized_posts():
    # Check whether the user is authorized
    meower.require_auth("header", ["oauth"], scopes=[], abort_on_none=False)
    
    # Get user's following list
    following = []
    for relation in meower.db.relationships.find({"follower": request.user.id}, projection={"followed": 1}):
        following.append(relation["followed"])

    # Get posts
    posts = meower.search_items("posts", {"$or": [{"author": {"$in": following}}, {"meows": {"$in": following}}], "deleted": False})

    # Convert posts
    for i in range(len(posts)):
        posts[i] = meower.Post(meower, posts[i]).public(authed_user=request.user.id)

    # Return payload
    return meower.resp(100, {"posts": posts})

@bp.route("/top", methods=["GET"])
def get_top_posts():
    # Check whether the user is authorized
    meower.require_auth("header", ["oauth"], scopes=[])

    # Get posts
    posts = meower.search_items("posts", {}, pipeline_items=[
        {
            "$match": {
                "created": {
                    "$gt": (meower.time() - 2592000000)
                }
            }
        },
        {
            "$addFields": {
                "reputation": {
                    "$subtract": [
                        {
                            "$add": [
                                "$likes"
                                "$meows"
                            ]
                        },
                        {
                            "$pow": [
                                {
                                    "$multiply": [
                                        {
                                            "$subtract": [
                                                meower.time(),
                                                "$created"
                                            ]
                                        },
                                        10
                                    ]
                                },
                                -5
                            ]
                        }
                    ]
                }
            }
        },
        {
            "$sort": {
                "reputation": -1
            }
        }
    ])

    # Convert posts
    for i in range(len(posts)):
        posts[i] = meower.Post(meower, posts[i]).public(authed_user=request.user.id)

    # Return payload
    return meower.resp(100, {"posts": posts})