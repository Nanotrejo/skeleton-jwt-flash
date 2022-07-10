from flask import abort, make_response, request
from flask.json import jsonify

from app import app
from app.jwt.auth import admin_required, auth_required


@app.route("/api/user-sample", methods=["GET", "POST"])
@auth_required
def sample_api():
    """
    Example API
    """
    if request.method == "GET":
        return make_response(jsonify({"example": 123}))
    elif request.method == "POST":
        data = request.get_json()
        app.logger.debug("payload: %d", data["example"])
        return make_response(jsonify({"example": data["example"] * 2}))
    else:
        abort(405)


@app.route("/api/admin-sample", methods=["GET", "POST"])
@admin_required
def admin_api():
    """
    Example API
    """
    if request.method == "GET":
        return make_response(jsonify({"example": 123}))
    elif request.method == "POST":
        data = request.get_json()
        app.logger.debug("payload: %d", data["example"])
        return make_response(jsonify({"example": data["example"] * 2}))
    else:
        abort(405)
