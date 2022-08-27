from flask import Blueprint, request, render_template
from flask import current_app as app

admin = Blueprint("admin_blueprint", __name__)