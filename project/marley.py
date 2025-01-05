import requests

from flask import redirect, render_template, session,request
from functools import wraps
from urllib.parse import quote


def apology(message, code=400):
    """Render an apology to the user."""
    referrer = request.referrer or "/"
    return render_template("apology.html",referrer=referrer, top=code, bottom=message), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"
