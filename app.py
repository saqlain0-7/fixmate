"""SOLUTIONS / FixMate Pro - local services marketplace.

Run:  python app.py        (then open http://127.0.0.1:5000)
"""
import os
from datetime import date, timedelta

from flask import Flask, redirect, render_template, request, url_for

from config import Config
from db import close_db, init_db
import helpers


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    init_db(app)
    app.teardown_appcontext(close_db)
    app.before_request(helpers.check_csrf)

    # ---- template helpers ------------------------------------------------
    app.jinja_env.filters.update(
        status_label=helpers.status_label, slug=helpers.slugify,
        fmt_date=helpers.fmt_date, short_name=helpers.short_name,
        initials=helpers.initials)
    app.jinja_env.globals.update(can_review=helpers.can_review)

    @app.context_processor
    def inject_globals():
        user = helpers.current_user()
        cfg = app.config
        today = date.today()
        return dict(today=today.isoformat(),
                    max_date=(today + timedelta(days=cfg["MAX_BOOKING_DAYS_AHEAD"])).isoformat(),current_user=user, csrf_token=helpers.csrf_token,
                    nav_items=helpers.nav_items(user),
                    home_endpoint=helpers.home_endpoint(user),
                    SERVICES=cfg["SERVICES"], TIME_SLOTS=cfg["TIME_SLOTS"],
                    FEE=cfg["INSPECTION_FEE_RS"])

    # ---- blueprints -------------------------------------------------------
    from blueprints.public import bp as public_bp
    from blueprints.auth import bp as auth_bp
    from blueprints.customer import bp as customer_bp
    from blueprints.worker import bp as worker_bp
    from blueprints.admin import bp as admin_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(customer_bp, url_prefix="/customer")
    app.register_blueprint(worker_bp, url_prefix="/worker")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    # ---- old URLs keep working (redirect to the new routes) ---------------
    legacy = {
        "/available_workers": "public.workers",
        "/worker_dashboard": "worker.dashboard",
        "/customer_dashboard": "customer.dashboard",
        "/admin_report": "admin.dashboard",
        "/login_admin": "admin.login",
        "/register_customer": ("auth.register", {"role": "customer"}),
        "/register_worker": ("auth.register", {"role": "worker"}),
    }
    for path, target in legacy.items():
        endpoint, kwargs = (target, {}) if isinstance(target, str) else target

        def _redir(endpoint=endpoint, kwargs=kwargs):
            return redirect(url_for(endpoint, **kwargs, **request.args), 301)
        app.add_url_rule(path, endpoint=f"legacy{path.replace('/', '_')}", view_func=_redir)

    @app.route("/worker_profile/<int:worker_id>")
    def legacy_worker_profile(worker_id):
        return redirect(url_for("public.worker_profile", worker_id=worker_id), 301)

    # ---- error pages -------------------------------------------------------
    def _error(code, title, message):
        return render_template("error.html", code=code, title=title, message=message), code

    @app.errorhandler(400)
    def bad_request(e):
        return _error(400, "Something went wrong", getattr(e, "description", "Bad request."))

    @app.errorhandler(403)
    def forbidden(e):
        return _error(403, "Not allowed", "You don't have permission to view this page.")

    @app.errorhandler(404)
    def not_found(e):
        return _error(404, "Page not found", "The page you're looking for doesn't exist or was moved.")

    @app.errorhandler(413)
    def too_large(e):
        return _error(413, "File too large", "Uploads must be 5 MB or smaller.")

    @app.errorhandler(500)
    def server_error(e):
        return _error(500, "Server error", "Something broke on our side. Please try again.")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"])
