# Import needed modules
from flask import Flask, request, send_file
from apiv0.utils.supporter import Supporter
from apiv0.utils.security import Security
from apiv0.utils.database import Database
from apiv0.utils.respond import Respond
import secrets
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize API object
meower = Flask(__name__)

# Initialize supporter
Supporter(meower, request)

# Initialize security
Security(meower, request)

# Initialize database
Database(meower, request)

# Initialize respond
Respond(meower, request)

# Upload file endpoint
@meower.route("/", methods=["POST"])
def upload_file():
    pass

@meower.route("/<file_token>", methods=["GET", "DELETE"])
def view_file(file_token):
    # Get information about the file
    file_info = meower.db.uploads.find_one({"tokens": {"$all": [file_token]}})
    if file_info is None:
        return meower.resp(103)

    # Ratelimits
    if meower.check_ratelimit("file_views-{0}".format(file_info["_id"]), request.remote_addr):
        return meower.resp(106)
    else:
        meower.ratelimit("file_views-{0}".format(file_info["_id"]), request.remote_addr, burst=10, seconds=10)

    # Send file
    if file_info["blocked"]: # Check if the file is blocked
        return send_file("uploads/blocked")
    else:
        return send_file("uploads/{0}".format(file_info["_id"]))

meower.run(host="0.0.0.0", port=3002)