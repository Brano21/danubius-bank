"""Application factory.

Weekly modules unlock CUMULATIVELY and - critically - a locked week's code is
never imported, so its routes cannot be reached even by guessing a URL. This is
the enforcement point for brief requirement #5: weekly modules stay OFF until
turned on. Raising WEEK and redeploying is the only way to expose a module.
"""
from flask import Flask

from .config import Config
from . import db


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.teardown_appcontext(db.close_db)

    week = app.config["WEEK"]

    # --- Week 1 (always on) ------------------------------------------------
    from .modules.week1_login import bp as week1_bp
    app.register_blueprint(week1_bp)

    # --- Week 2 ------------------------------------------------------------
    if week >= 2:
        from .modules.week2_api import bp as week2_bp
        app.register_blueprint(week2_bp)

    # --- Week 3 ------------------------------------------------------------
    if week >= 3:
        from .modules.week3_llm import bp as week3_bp
        app.register_blueprint(week3_bp)

    # --- Week 4 ------------------------------------------------------------
    if week >= 4:
        from .modules.week4_evidence.web import bp as week4_bp
        app.register_blueprint(week4_bp)

    @app.context_processor
    def inject_globals():
        # `client` is made available to every template so the nav can render
        # the right links on any page (returns None when not logged in).
        from .auth import current_client
        return {"WEEK": week, "bank_name": "Danubius Bank", "client": current_client()}

    # Branded error pages so unexpected failures look like the bank, not a raw
    # Flask stack page. NOTE: injectable endpoints (e.g. the W1-02 transaction
    # search) still surface the DB error inline on purpose - that is the intended
    # "it's injectable" signal; these generic handlers only cover the rest.
    from flask import render_template

    @app.errorhandler(404)
    def handle_404(_e):
        return render_template("error.html", code=404, title="Page not found",
                               message="We couldn't find the page you were "
                                       "looking for."), 404

    @app.errorhandler(500)
    def handle_500(_e):
        db.close_db()  # drop a possibly-broken connection so the page can render
        try:
            return render_template("error.html", code=500, title="Service error",
                                   message="Something went wrong on our side. "
                                           "Please try again in a moment."), 500
        except Exception:  # noqa: BLE001 - never recurse into another 500
            return "Internal Server Error", 500

    return app
