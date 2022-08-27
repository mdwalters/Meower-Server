from flask import Blueprint
import os
from passlib.hash import bcrypt
from jinja2 import Template
import requests

bp = Blueprint("users_utils", __name__)

class Users:
    def __init__(self, meower, request):
        self.meower = meower
        self.request = request

        # Add functions to Meower class
        self.meower.create_user = self.create_user
        self.meower.get_userid = self.get_userid
        self.meower.get_user = self.get_user
        self.meower.send_email = self.send_email
        # self.meower.export_data = self.export_data - gonna complete later

    def create_user(self, username, password, id=None, created=None, badges=[], child=False, bot=None):
        # Check if account already exists
        if self.meower.db.users.find_one({"lower_username": username.lower()}) is not None:
            return None

        # Hash password
        if password is not None:
            password = bcrypt.hash(password)

        # Create ID
        if id is None:
            id = self.meower.uid()

        # Create creation timestamp
        if created is None:
            created = self.meower.time()

        # Create userdata
        userdata = {
            "_id": id,
            "username": username,
            "lower_username": username.lower(),
            "bot": bot,
            "last_ip": None,
            "created": created,
            "delete_after": None,
            "config": {
                "theme": "orange",
                "dark": False,
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
                "badges": badges,
                "social_links": [],
                "last_seen": None
            },
            "permissions": {
                "ban_status": None,
                "supporter": False,
                "mod_lvl": 0
            },
            "authorized_oauth": {},
            "security": {
                "email": None,
                "password": password,
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
                "child": child,
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
        self.meower.db.users.insert_one(userdata)

        return userdata

    def get_userid(self, username, abort_on_fail=False):
        userdata = self.meower.db.users.find_one({"lower_username": username.lower()})
        
        if userdata is None:
            if abort_on_fail:
                return self.meower.resp(103, msg="Invalid username", abort=True)
            else:
                return None
        else:
            return userdata["_id"]

    def get_user(self, username=None, userid=None, abort_on_fail=False, deleted_on_fail=True):
        if (username is not None) and (len(username) < 20):
            userdata = self.meower.db.users.find_one({"lower_username": username.lower()})
        elif userid is not None:
            userdata = self.meower.db.users.find_one({"_id": userid})
        else:
            userdata = None

        if (userdata is None) and abort_on_fail:
            return self.meower.resp(103, msg="Invalid username", abort=True)
        elif (userdata is None) and deleted_on_fail:
            userdata = self.meower.db.users.find_one({"_id": "deleted"})
        
        # Return user object
        if userdata is not None:
            return self.meower.User(self.meower, userdata)
        else:
            return None

    def send_email(self, template, email, username, subject, data):
        # Render template
        with open("apiv0/email_templates/{0}.html".format(template), "r") as f:
            body = Template(f.read()).render(data)

        # Create request payload
        payload = {
            "personalizations": [{
                "to": [{
                    "email": email,
                    "name": username
                }],
                "dkim_domain": os.getenv("EMAIL_DOMAIN"),
                "dkim_selector": "mailchannels",
                "dkim_private_key": os.getenv("EMAIL_DKIM_KEY")
            }],
            "from": {
                "email": os.getenv("NO_REPLY_EMAIL"),
                "name": "Meower"
            },
            "subject": subject,
            "content": [{
                "type": "text/html",
                "value": body
            }]
        }

        # Send email request
        return requests.post(os.getenv("EMAIL_WORKER_URL"), headers={"X-Auth-Token": os.getenv("EMAIL_WORKER_TOKEN")}, json=payload).text

    """
    def export_data(self, user):
        # Create export ID
        export_id = self.meower.uid()

        # Create directory to store exported data
        os.mkdir("apiv0/data_exports/{0}".format(export_id))
        os.mkdir("apiv0/data_exports/{0}/sessions".format(export_id))
        os.mkdir("apiv0/data_exports/{0}/posts".format(export_id))
        os.mkdir("apiv0/data_exports/{0}/chats".format(export_id))
        os.mkdir("apiv0/data_exports/{0}/oauth_apps".format(export_id))
        os.mkdir("apiv0/data_exports/{0}/bots".format(export_id))

        # Create user.json
        userdata = self.meower.db.users.find_one({"_id": user})
        if userdata is not None:
            exported_userdata = copy.deepcopy(userdata)
            for item in ["email", "password", "webauthn", "totp", "moderation_history"]:
                exported_userdata["security"][item] = None
            with open("apiv0/data_exports/{0}/user.json".format(export_id), "w") as f:
                json.dump(exported_userdata, f, indent=4)

        # Get all sessions
        sessions = self.meower.db.sessions.find({"user": user})
        for session in sessions:
            session["token"] = None
            session["email"] = None
            session["refresh_token"] = None
            session["previous_refresh_tokens"] = None
            with open("apiv0/data_exports/{0}/sessions/{1}.json".format(export_id, session["_id"]), "w") as f:
                json.dump(session, f, indent=4)

        # Get all posts
        index = {"order_key": "t", "order_mode": "Descending"}
        posts = self.meower.db.posts.find({"u": user}).sort("t", pymongo.DESCENDING)
        for post in posts:
            if post["post_origin"] not in os.listdir("apiv0/data_exports/{0}/posts".format(export_id)):
                os.mkdir("apiv0/data_exports/{0}/posts/{1}".format(export_id, post["post_origin"]))
                index[post["post_origin"]] = []
            with open("apiv0/data_exports/{0}/posts/{1}/{2}.json".format(export_id, post["post_origin"], post["_id"]), "w") as f:
                json.dump(post, f, indent=4)
            index[post["post_origin"]].append(post["_id"])
        with open("apiv0/data_exports/{0}/chats/index.json".format(export_id), "w") as f:
            json.dump(index, f, indent=4)

        # Get all chats
        chats = self.meower.db.chats.find({"members": {"$all": [user]}, "deleted": False}).sort("nickname", pymongo.DESCENDING)
        for chat in chats:
            with open("apiv0/data_exports/{0}/chats/{1}.json".format(export_id, chat["_id"]), "w") as f:
                json.dump(chat, f, indent=4)

        # Get OAuth apps
        oauth_apps = self.meower.db.oauth.find({"owner": user})
        for app in oauth_apps:
            app["secret"] = None
            with open("apiv0/data_exports/{0}/oauth_apps/{1}.json".format(export_id, app["_id"]), "w") as f:
                json.dump(app, f, indent=4)

        # Create ZIP file
        if "{0}.zip".format(user) in os.listdir("apiv0/data_exports"):
            os.remove("apiv0/data_exports/{0}.zip".format(user))
        shutil.make_archive("apiv0/data_exports/{0}".format(user), "zip", "apiv0/data_exports/{0}".format(export_id))

        # Delete export directory
        shutil.rmtree("apiv0/data_exports/{0}".format(export_id))

        # Create session for downloading the package
        session = self.meower.create_session(0, user, str(secrets.token_urlsafe(32)), expires=86400, action="download-data")

        # Send email
        if userdata["security"]["email"] is None:
            email = None
        else:
            email = self.meower.decrypt(userdata["security"]["email"]["encryption_id"], userdata["security"]["email"]["encrypted_email"])
        if email is not None:
            with open("apiv0/email_templates/confirmations/download_data.html", "r") as f:
                email_template = Template(f.read()).render({"username": userdata["username"], "token": session["token"]})
            Thread(target=self.meower.send_email, args=(email, userdata["username"], "Your data package is ready", email_template,), kwargs={"type": "text/html"}).start()
    """

class User:
    def __init__(self, meower, data):
        self.id = data["_id"]
        self.meower = meower # Have to add this just for **1** value AAAAAAAAAAAAAAAAAAA
        self.data = data

    def client(self):
        return {
            "id": self.data["_id"],
            "username": self.data["username"],
            "bot": self.data["bot"],
            "created": self.data["created"],
            "permissions": self.data["permissions"],
            "profile": self.data["profile"],
            "config": self.data["config"],
            "privacy": self.data["privacy"],
            "guardian": self.data["guardian"]
        }

    def public(self):
        return {
            "id": self.data["_id"],
            "username": self.data["username"],
            "bot": self.data["bot"],
            "banned": (self.data["permissions"]["ban_status"] is not None),
            "created": self.data["created"],
            "profile": {
                "pfp": self.data["profile"]["pfp"],
                "quote": self.data["profile"]["quote"],
                "badges": self.data["profile"]["badges"],
                "status": self.data["profile"]["status"],
                "last_seen": self.data["profile"]["last_seen"]
            },
            "private": self.data["privacy"]["private"],
            "followers": self.meower.db.users.count_documents({"relations.following": {"$all": [self.data["_id"]]}}),
            "following": len(self.data["relations"]["following"])
        }

    def pre_login(self):
        return {
            "id": self.data["_id"],
            "username": self.data["username"],
            "bot": self.data["bot"],
            "created": self.data["created"],
            "pfp": self.data["profile"]["pfp"],
            "dark_mode": self.data["config"]["dark"],
            "auth_methods": {
                "password": (self.data["security"]["password"] is not None),
                "webauthn": (len(self.data["security"]["webauthn"]) > 0)
            }
        }

    def legacy_client(self):
        return {
            "_id": self.data["username"],
            "uuid": self.data["_id"],
            "lower_username": self.data["lower_username"],
            "created": self.data["created"],
            "pfp_data": 1,
            "lvl": self.data["permissions"]["mod_lvl"],
            "banned": (self.data["permissions"]["ban_status"] is not None),
            "quote": self.data["profile"]["quote"],
            "unread_inbox": False,
            "theme": "orange",
            "mode": (self.data["config"]["dark"] == False),
            "layout": "new",
            "email": "",
            "debug": False,
            "sfx": self.data["config"]["sfx"],
            "bgm": self.data["config"]["bgm"]["enabled"],
            "bgm_song": 2
        }

    def legacy_public(self):
        return {
            "_id": self.data["username"],
            "uuid": self.data["_id"],
            "lower_username": self.data["lower_username"],
            "created": self.data["created"],
            "pfp_data": 1,
            "quote": self.data["profile"]["quote"],
            "lvl": self.data["permissions"]["mod_lvl"],
            "banned": (self.data["permissions"]["ban_status"] is not None),
        }