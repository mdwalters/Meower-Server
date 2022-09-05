from flask import Blueprint
import flask
import json

bp = Blueprint("response", __name__)

class Respond:
    def __init__(self, meower, request):
        self.meower = meower
        self.request = request
        
        # Load status codes
        with open("apiv0/statuses.json", "r") as f:
            self.statuses = json.load(f)
            self.success_codes = set([0,100])

        # Add functions to Meower class
        self.meower.resp = self.resp

    def resp(self, code: int, data: dict=None, msg=None, abort=False, force_success=False):
        # Invalid response code
        if str(code) not in self.statuses:
            code = 104
            msg = "Invalid status code"

        # Create response payload
        if data is None:
            data = {}
        data["success"] = (force_success or (code in self.success_codes))
        data["code"] = code

        # Add custom message if there is one
        if msg is not None:
            data["msg"] = msg
        else:
            data["msg"] = self.statuses[str(code)]["msg"]

        # Return response
        if abort:
            return flask.abort(flask.Response(json.dumps(data), content_type="text/json", status=self.statuses[str(code)]["http"]))
        else:
            return flask.Response(json.dumps(data), content_type="text/json", status=self.statuses[str(code)]["http"])