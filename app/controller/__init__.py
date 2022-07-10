import datetime
import json

from bson import ObjectId
from flask.json import jsonify


class JSONEncoder(json.JSONEncoder):
    def default(self, o):

        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


def response(status: int, name: str, description: str, payload=None):
    if payload is None:
        payload = {}
    return (
        jsonify(
            {
                "statusCode": status,
                "name": name,
                "date": datetime.datetime.now(),
                "description": description,
                "payload": json.loads(JSONEncoder().encode(payload)),
            }
        ),
        status,
    )
