from flask import Blueprint

bp = Blueprint("posts_utils", __name__)

class Posts:
    def __init__(self, meower, request):
        self.meower = meower
        self.request = request

        # Add functions to Meower class
        self.meower.personalized_home = self.personalized_home
        self.meower.create_home_post = self.create_home_post

    def personalized_home(self):
        db_cursor = self.meower.db.posts.aggregate([
            {
                "$match": {
                    "$or": [
                        {
                            "author": {"$in": [self.request.user.data["relations"]["following"]]}
                        },
                        {
                            "meows": {"$in": [self.request.user.data["relations"]["following"]]}
                        }
                    ]
                }
            },
            {
                "$addFields": {
                    "id": "$_id",
                    "liked": self.request.user.id,
                    "meowed": self.request.user.id,
                    "likes": {"$size": "$likes"},
                    "meows": {"$size": "$meows"}
                }
            },
            {
                "$project": {
                    "id": 1,
                    "author": 1,
                    "content": 1,
                    "attatchment": 1,
                    "likes": 1,
                    "meows": 1,
                    "liked": 1,
                    "meowed": 1,
                    "created": 1
                }
            },
            {
                "$sort": {
                    "created": -1
                }
            },
            {
                "$limit": 25
            }
        ])
        posts = []
        for item in db_cursor:
            print(item)
            item["author"] = self.meower.get_user(userid=item["author"]).post()
            posts.append(item)
        return posts

    def create_home_post(self, user, content, attatchment, nick=None):
        post_data = {
            "_id": self.meower.uid(),
            "author": user,
            "nick": nick,
            "content": content,
            "attatchment": attatchment,
            "likes": [],
            "meows": [],
            "moderator_notes": {},
            "created": self.meower.time(),
            "deleted": False
        }
        self.meower.db.posts.insert_one(post_data)
        return self.meower.Post(self.meower, post_data)

class Post:
    def __init__(self, meower, data):
        self.id = data["_id"]
        self.meower = meower
        self.data = data

    def public(self, authed_user=None):
        # Get author user object
        self.data["author"] = self.meower.get_user(userid=self.data["author"]).post()

        # Check if the user that is logged in has liked/meowed the post
        if authed_user is not None:
            self.data["liked"] = True
            self.data["meowed"] = True
        else:
            self.data["liked"] = False
            self.data["meowed"] = False

        # Return post
        return self.data