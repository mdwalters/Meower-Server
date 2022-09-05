from flask import Blueprint, request
from flask import current_app as meower
import jwt

bp = Blueprint("sessions_utils", __name__)

class Sessions:
    def __init__(self, meower, request):
        self.meower = meower
        self.request = request

        # Add functions to Meower class
        self.meower.gen_jwt_standalone = self.gen_jwt_standalone
        self.meower.get_jwt_standalone = self.get_jwt_standalone
        self.meower.gen_jwt_session = self.gen_jwt_session
        self.meower.get_jwt_session = self.get_jwt_session
        self.meower.require_auth = self.require_auth

    def gen_jwt_standalone(self, ttype, user, claims: dict, expires: int):
        """
        Generates and signs a standalone session object.

        ttype: type of token
        user: user of token
        claims: dictionary of claims to be included
        expires: milliseconds the token should be allowed for

        Returns the signed base64 standalone JWT.
        """

        # Create and sign JWT
        claims["uid"] = self.meower.uid()
        claims["t"] = ttype
        claims["u"] = user
        claims["iat"] = self.meower.time()
        claims["eat"] = (self.meower.time() + expires)
        jwt_standalone = jwt.encode(claims, self.meower.jwt_secret, algorithm="HS256").decode()

        # Return signed JWT
        return jwt_standalone

    def get_jwt_standalone(self, jwt_token: str):
        """
        Get a standalone session object from a JWT token.

        jwt_token: base64 encoded JWT token

        Returns standalone session object, or None on failure.
        """

        # Attempt to decode and verify the token
        try:
            decoded_jwt = jwt.decode(jwt_token, self.meower.jwt_secret, verify=True)
        except:
            return None

        # Check if token has expired or is disallowed
        if (meower.time() > decoded_jwt["eat"]) or (meower.db.blocked_jwts.find_one({"_id": decoded_jwt["uid"] is not None})):
            return None

        return decoded_jwt

    def gen_jwt_session(self, uid: str, ttype: str, version: int):
        """
        Signs a JWT session token pair.

        uid: Meower UID of session
        ttype: type of session
        version: version of session

        Returns the signed base64 access and refresh JWT.
        """

        # Create and sign access JWT
        access_jwt = jwt.encode({"uid": uid, "t": ttype, "v": version}, self.meower.jwt_secret, algorithm="HS256").decode()

        # Create and sign refresh JWT
        refresh_jwt = jwt.encode({"uid": uid, "t": "refresh", "v": version}, self.meower.jwt_secret, algorithm="HS256").decode()

        # Return signed JWTs
        return access_jwt, refresh_jwt

    def get_jwt_session(self, jwt_token: str):
        """
        Gets a session object from a JWT token.

        jwt_token: base64 encoded JWT token

        Returns session object, or None on failure.
        """

        # Attempt to decode and verify the token
        try:
            decoded_jwt = jwt.decode(jwt_token, self.meower.jwt_secret, verify=True)
        except:
            return None

        # Get session data from token UID
        session = self.meower.db.sessions.find_one({"_id": decoded_jwt["uid"], ("refresh_expires" if (decoded_jwt["t"] == "refresh") else "access_expires"): {"$gt": meower.time()}})

        if session is None:
            return None
        elif decoded_jwt["v"] != session["v"]:
            # Delete session if token is signed but has wrong version, as some token re-use could be happening
            self.meower.db.sessions.delete_one({"_id": decoded_jwt["uid"]}) 
            return None
        else:
            if decoded_jwt["t"] == "refresh": # Check if it's a refresh token or not
                session["t"] = "refresh"
            return session

    def require_auth(self, auth_type, ttypes, standalone=False, scopes=[], abort_on_none=True, allow_banned=False, allow_unapproved=False, mod_level=0):
        # Get token input
        if auth_type == "args": # Get token from URI args
            if "code" in request.args:
                token = request.args.get("code")
        elif auth_type == "body": # Get token from JSON body
            if "code" in request.json:    
                token = request.json["code"]
            elif "token" in request.json:
                token = request.json["token"]
        elif auth_type == "header": # Get token from header
            token = request.headers.get("Authorization")

        # Clean token input
        if not ((token == None) or (token == "") or (len(token) > 350)):
            token = token.replace("Bearer ", "").strip()
            if standalone:
                request.session = meower.get_jwt_standalone(token)
            else:
                request.session = meower.get_jwt_session(token)

        # Check if session is valid
        if (request.session is None) or (self.request.session["t"] not in ttypes):
            if abort_on_none:
                return self.meower.resp(11, msg="Invalid authorization token", abort=True)
            else:
                return

        # Check session scopes
        if not standalone:
            if not all(scope in request.session["scopes"] for scope in scopes):
                return self.meower.resp(11, msg="Invalid authorization token", abort=True)

        # Check user
        userdata = self.meower.db.users.find_one({"_id": request.session["u"]})
        if userdata is None or userdata["deleted"] or (userdata["permissions"]["mod_lvl"] < mod_level):
            # Account is deleted, or is not high enough mod level
            return self.meower.resp(11, msg="Invalid authorization token", abort=True)
        elif (not allow_banned) and (userdata["permissions"]["ban_status"] is not None) and (userdata["permissions"]["ban_status"]["expires"] > meower.time()):
            # Account is currently banned
            return self.meower.resp(18, {"expires": request.user.data["permissions"]["ban_status"]["expires"], "reason": request.user.data["permissions"]["ban_status"]["reason"]}, abort=True)
        elif not (allow_unapproved or userdata["guardian"]["approved"]):
            # Account is a child and has not been approved by a guardian
            return meower.resp(105, msg="You need to verify your parent's email or link your parent's account before continuing")
        else:
            request.user = meower.User(meower, userdata)
            request.user_cache[request.user.id] = request.user