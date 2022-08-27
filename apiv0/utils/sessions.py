from flask import Blueprint
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

    def gen_jwt_standalone(self, claims: dict, expires: int):
        """
        Generates and signs a standalone session object.

        claims: dictionary of claims to be included
        expires: milliseconds the token should be allowed for

        Returns the signed base64 standalone JWT.
        """

        # Create and sign JWT
        claims["id"] = self.meower.uid()
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
        session = self.meower.db.sessions.find_one({"_id": decoded_jwt["uid"]})
        if session is None:
            return None
        elif decoded_jwt["v"] != session["v"]:
            # Delete session if token is signed but has wrong version, as some token re-use could be happening
            self.meower.db.sessions.delete_one({"_id": decoded_jwt["uid"]}) 
            return None
        else:
            if decoded_jwt["type"] == "refresh": # Check if it's a refresh token or not
                session["type"] = "refresh"
            #return Session(meower, session)