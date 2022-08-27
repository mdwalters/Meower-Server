# Import needed modules
from flask import Flask, request
import os
import json
from importlib import import_module
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize API object
meower = Flask(__name__)

# Initialize server and process ID
meower.sid = os.getenv("SERVER_ID")
meower.pid = os.getpid()

# Test JWT secret
meower.jwt_secret = "abc"

# Get blueprints list
with open("blueprints.json", "r") as f:
	blueprints_list = json.load(f)

# Register blueprints
for bp_info in blueprints_list:
	# Register blueprint to Meower class
	module = import_module(bp_info["module"])
	meower.register_blueprint(module.bp, url_prefix=bp_info["prefix"])

	# Add classes to Meower class
	for class_name in bp_info["classes"]:
		setattr(meower, class_name, getattr(module, class_name)(meower, request))

	# Add template classes to Meower class
	for class_name in bp_info["templates"]:
		setattr(meower, class_name, getattr(module, class_name))

	print("Registered {0} blueprint".format(bp_info["module"]))

# Initialize CORS
from flask_cors import CORS
CORS(meower, resources={r'*': {'origins': '*'}})

# Run Flask app
meower.run(host="0.0.0.0", port=3000, debug=True)


"""
# Initialize Utils
class Accounts: pass
meower.Accounts = Accounts
from apiv0.utils import Utils, Session
utils = Utils(meower, request)
meower.all_oauth_scopes = utils.all_oauth_scopes
meower.first_party_oauth_scopes = utils.first_party_oauth_scopes
meower.log = utils.log
meower.uid = utils.uid
meower.timestamp = utils.timestamp
meower.time = utils.time
meower.foundation_session = utils.foundation_session
meower.check_ratelimit = utils.check_ratelimit
meower.ratelimit = utils.ratelimit
meower.check_for_bad_chars_username = utils.check_for_bad_chars_username
meower.check_captcha = utils.check_captcha
meower.filter = utils.filter
meower.user_status = utils.user_status
meower.export_data = utils.export_data
meower.send_payload = utils.send_payload
meower.encrypt = utils.encrypt
meower.decrypt = utils.decrypt
meower.is_valid_email = utils.is_valid_email
meower.send_email = utils.send_email
meower.init_db = utils.init_db
meower.get_userid = utils.get_userid
meower.get_user = utils.get_user
meower.check_for_json = utils.check_for_json
meower.check_for_params = utils.check_for_params
meower.require_auth = utils.require_auth
meower.Session = Session

# Initialize Objects
from apiv0.objects import User
meower.User = User

# Initialize encryption
utils.init_encryption()

# Add development JWT token
meower.jwt_secret = "meower"

# Initialize Responder
from apiv0.respond import respond
meower.resp = respond


# Initialize database


# Load profanity filter
from better_profanity import profanity
meower.profanity = profanity
meower.log("Loading profanity filter...")
filter = meower.db.config.find_one({"_id": "filter"})
meower.profanity.load_censor_words(whitelist_words=filter["whitelist"])
meower.profanity.add_censor_words(custom_words=filter["blacklist"])
meower.blocked_usernames = filter["blocked_usernames"]

# Set repair mode and scratch deprecated state
status = meower.db.config.find_one({"_id": "status"})
for key, value in status.items():
	if key != "_id":
		setattr(meower, key, value)
"""