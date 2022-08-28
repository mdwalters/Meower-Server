from flask import Blueprint
import string
from better_profanity import profanity as better_profanity

bp = Blueprint("checks_utils", __name__)

class Checks:
    def __init__(self, meower, request):
        self.meower = meower
        self.request = request

        # Permitted list of characters for usernames
        self.permitted_chars_username = []
        self.permitted_chars_username.extend(string.ascii_letters)
        self.permitted_chars_username.extend(string.digits)
        self.permitted_chars_username.extend([".", "-", "_"])

        # Load profanity blocklist
        filter_config = self.meower.db.config.find_one({"_id": "filter"})
        self.moderate_profanity = filter_config["moderate"]
        self.strict_profanity = filter_config["strict"]
        self.blocked_usernames = filter_config["usernames"]

        # Add functions to Meower class
        self.meower.check_username = self.check_username
        self.meower.filter_profanity = self.filter_profanity
        self.meower.is_valid_email = self.is_valid_email
        self.meower.check_for_json = self.check_for_json
        self.meower.check_for_params = self.check_for_params

    def check_username(self, username):
        # Check if username is blocked
        if (username in self.blocked_usernames):
            return True

        # Filter any profanity in the username (this will cause an illegal character error to be raised)
        username = self.filter_profanity(username, 3)

        # Check if username contains an illegal character
        for char in username:
            if not char in self.permitted_chars_username:
                return True
        return False

    def filter_profanity(self, text, level):
        better_profanity.load_censor_words([[], self.moderate_profanity, self.strict_profanity, self.blocked_usernames][level])
        return better_profanity.censor(text)

    def is_valid_email(self, email):
        # Check if the email contains an @
        if "@" not in email:
            return False
        
        # Check if the email address domain is valid
        email = email.split("@")
        if (email[1].count(".") == 0) or email[1].startswith(".") or email[1].endswith("."):
            return False
        else:
            return True

    def check_for_json(self, data=[]):
        """
        id: JSON key
        t: expected datatype
        l_min: length minimum
        l_max: length maximum
        r_min: range minimum
        r_max: range maximum
        """

        error = None

        for item in data:
            # Run all checks specified
            if item["i"] not in self.request.json:
                error = "missing"
            elif ("t" in item) and (type(self.request.json[item["i"]]) != item["t"]):
                print(item)
                print(type(self.request.json[item["i"]]))
                print(item["t"])
                error = "datatype"
            elif ("l_min" in item) and (len(str(self.request.json[item["i"]])) < item["l_min"]):
                error = "tooShort"
            elif ("l_max" in item) and (len(str(self.request.json[item["i"]])) > item["l_max"]):
                error = "tooLong"
            elif (("r_min") in item) and (self.request.json[item["i"]] < item["r_min"]):
                error = "tooBig"
            elif (("r_max") in item) and (self.request.json[item["i"]] > item["r_max"]):
                error = "tooSmall"

            # Return if any errors
            if error is not None:
                if error == "datatype":
                    return self.meower.resp(102, {item["i"]: error}, msg="Invalid body field", abort=True)
                else:
                    return self.meower.resp(101, {item["i"]: error}, msg="Invalid body field", abort=True)

    def check_for_params(self, data=[]):
        for item in data:
            if item not in self.request.args:
                return self.meower.resp(101, {item["i"]: "missing"}, msg="Missing request argument", abort=True)