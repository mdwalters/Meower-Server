from flask import Blueprint
from datetime import datetime
from time import time as unix_epoch
import time
from threading import Thread

bp = Blueprint("supporter_utils", __name__)

class Supporter:
    def __init__(self, meower, request):
        self.meower = meower
        self.request = request

        # UID increment
        self.id_increment = 0

        # Add functions to Meower class
        self.meower.log = self.log
        self.meower.time = self.time
        self.meower.timestamp = self.timestamp
        self.meower.uid = self.uid

        # Start background task
        background_thread = Thread(target=self.background)
        background_thread.daemon = True
        background_thread.start()
    
    def background(self):
        while True:
            # Background task runs every 60 seconds
            time.sleep(60)

            # Reset ID increment
            self.id_increment = 0

            # Purge any expired sessions
            self.meower.db.sessions.delete_many({"type": {"$in": [0,1,3,4,6]}, "expires": {"$lt": self.time()}})
            self.meower.db.sessions.delete_many({"refresh_expires": {"$lt": self.time()}})

            # Purge accounts pending deletion
            users = self.meower.db.users.find({"security.delete_after": {"$lt": self.time()}})
            for user in users:
                # Delete posts
                self.meower.db.posts.delete_many({"u": user["_id"]})

                # Delete sessions
                self.meower.db.sessions.delete_many({"user": user["_id"]})

                # Delete OAuth apps
                oauth_apps = self.meower.db.oauth.find({"owner": user["_id"]})
                for app in oauth_apps:
                    oauth_users = self.meower.db.users.find({"security.oauth.authorized": {"$all": [app["_id"]]}})
                    for oauth_user in oauth_users:
                        oauth_user["security"]["oauth"]["authorized"].remove(app["_id"])
                        del oauth_user["security"]["oauth"]["scopes"][app["_id"]]
                        self.meower.db.users.update_one({"_id": oauth_user["_id"]}, {"$set": {"security.oauth": oauth_user["security"]["oauth"]}})
                    self.meower.db.oauth.delete_one({"_id": app["_id"]})

                # Delete chats
                chats = self.meower.db.chats.find({"members": {"$all": [user["_id"]]}})
                for chat in chats:
                    if chat["permissions"][user["_id"]] >= 3:
                        self.meower.db.chats.delete_one({"_id": chat["_id"]})
                    else:
                        chat["members"].remove(user["_id"])
                        del chat["permissions"][user["_id"]]
                        self.meower.db.chats.update_one({"_id": chat["_id"]}, {"$set": {"members": chat["members"]}})

                # Schedule bots for deletion
                self.meower.db.users.update_many({"owner": user["_id"]}, {"$set": {"security.delete_after": self.time()}})

                # Delete userdata
                self.meower.db.users.delete_one({"_id": user["_id"]})

    def log(self, msg, prefix=None):
        if prefix is None:
            print("{0}: {1}".format(self.timestamp(4), msg))
        else:
            print("[{0}] {1}: {2}".format(prefix, self.timestamp(4), msg))

    def time(self):
        # Milliseconds since the start of 1970
        return int(unix_epoch() * 1000)

    def timestamp(self, ttype, epoch=int(unix_epoch())):
        today = datetime.fromtimestamp(epoch)
        if ttype == 1:
            # Legacy timestamps
            return dict({
                "mo": str(datetime.now().strftime("%m")),
                "d": str(datetime.now().strftime("%d")),
                "y": str(datetime.now().strftime("%Y")),
                "h": str(datetime.now().strftime("%H")),
                "mi": str(datetime.now().strftime("%M")),
                "s": str(datetime.now().strftime("%S")),
                "e": int(unix_epoch())
            })
        elif ttype == 2:
            return str(today.strftime("%H%M%S"))
        elif ttype == 3:
            return str(today.strftime("%d%m%Y%H%M%S"))
        elif ttype == 4:
            return str(today.strftime("%m/%d/%Y %H:%M.%S"))
        elif ttype == 5:    
            return str(today.strftime("%d%m%Y"))

    def uid(self):
        """
        Unique IDs for Meower:

        1) Milliseconds since the start of 2020
        2) The ID of the server it was created on
        3) The process ID of the server instance
        4) An incremental counter that is reset every minute 
        """

        # Add increment
        self.id_increment += 1

        # Generate and return uid
        return (str(self.time()) + str(self.meower.sid) + str(self.meower.pid) + str(self.id_increment))