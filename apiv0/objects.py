class Session:
    def __init__(self, meower, data):
        self.data = data
        self.id = self.data["_id"]
        self.user = meower.get_user(userid=self.data["user"])
        self.type = self.data["type"]
        self.app = self.data["app"]
        self.scopes = self.data["scopes"]

class Chat:
    def __init__(self, meower, data):
        for key, value in data.items():
            setattr(self, key, value)

class Post:
    def __init__(self, meower, data):
        for key, value in data.items():
            setattr(self, key, value)

class Comment:
    def __init__(self, meower, data):
        for key, value in data.items():
            setattr(self, key, value)

class ChatMessage:
    def __init__(self, meower, data):
        for key, value in data.items():
            setattr(self, key, value)

class InboxMessage:
    def __init__(self, meower, data):
        for key, value in data.items():
            setattr(self, key, value)