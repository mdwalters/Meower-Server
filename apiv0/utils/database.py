from flask import Blueprint
import pymongo
import json

bp = Blueprint("database_utils", __name__)

class Database:
    def __init__(self, meower, request):
        self.meower = meower
        self.request = request

        # Init DB
        self._init_db()

    def _init_db(self):
        self.meower.log("Connecting to MongoDB...")
        try:
            self.meower.db = pymongo.MongoClient("mongodb://localhost:27017")["meowerserver"]
        except pymongo.InvalidURI:
            self.meower.log("Database URI is malformed! Please check it and try again.")
            exit()
        except pymongo.InvalidName:
            self.meower.log("Database name is malformed! Please check it and try again.")
            exit()
        except pymongo.ConnectionFailure:
            self.meower.log("A connection could not be made to the database! Is MongoDB running and accepting connections?")
            exit()
        except pymongo.NetworkTimeout:
            self.meower.log("The database took too long to respond! Is MongoDB running and accepting connections?")
            exit()
        except Exception as err:
            self.meower.log("An unknown error occurred while trying to connect to the database: {0}".format(str(err)))
            exit()
        else:
            with open("db_template.json", "r") as f:
                db_data = json.loads(f.read())
            for collection_name, collection_data in db_data.items():
                for index_name in collection_data["indexes"]:
                    try:
                        self.meower.db[collection_name].create_index(index_name)
                    except:
                        pass
                for item in collection_data["items"]:
                    try:
                        self.meower.db[collection_name].insert_one(item)
                    except:
                        pass
            self.meower.log("Database collections: {0}".format(self.meower.db.list_collection_names()))