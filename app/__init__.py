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
        from .modules.week4_evidence import bp as week4_bp
        app.register_blueprint(week4_bp)

    @app.context_processor
    def inject_globals():
        return {"WEEK": week, "bank_name": "Danubius Bank"}

    return app
