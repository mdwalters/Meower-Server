from flask import Blueprint
from apiv0.websocket.server import server
from threading import Thread

bp = Blueprint("websocket_server", __name__)

class WebSocket:
    def __init__(self, meower, request):
        # Set version
        self.version = "0.1.0"

        # Init CloudLink
        cl = server(self, True)
        cl.setMOTD(True, "Meower Beta 6 WebSocket server")
        cl.loadCustomCommands(Meower, (meower, request))
        cl.disableCommands(["link", "unlink", "gmsg", "gvar", "setid"])

        # Add CloudLink server to Meower class
        meower.ws = cl

        # Run CloudLink server thread
        server_thread = Thread(target=cl.run, kwargs={"host": "0.0.0.0", "port": 3001})
        server_thread.daemon = True
        server_thread.start()

class Meower:
    def __init__(self, cloudlink, extra):
        self.cl = cloudlink
        self.meower, self.request = extra