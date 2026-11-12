"""The admin website (owner/staff only). Every page except the login needs a logged-in admin."""
from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for

import otp as otp_helpers
import security
import services_admin as svc
from db import fetch_one
from services_admin import AdminError, FormError
from validators import clean, parse_int
from werkzeug.security import check_password_hash, generate_password_hash

bp = Blueprint("admin", __name__)
PENDING = "pending_admin"          # session key: "this admin typed the right password and now needs the email code"
_DUMMY_HASH = generate_password_hash("not-a-real-password")


@bp.before_request
def protect_everything():
    """One gate for the whole admin area. Only the login page is open."""
    if request.endpoint in ("admin.login", "admin.verify", "admin.verify_resend"):
        return None
    if g.user is None:
        return redirect(url_for("admin.login", next=request.full_path.rstrip("?")))
    if g.user["role"] != "admin":
        abort(403)
    return None


def _back(default, target=None):
    return security.safe_next(target or request.form.get("next"), default)


# ------------------------------------------------------------------ login / logout
@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user and g.user["role"] == "admin":
        return redirect(url_for("admin.dashboard"))
    email, error = "", ""
    if request.method == "POST":
        email = clean(request.form.get("email"), 120).lower()
        pw = request.form.get("password", "")
        key = f"admin|{request.remote_addr}|{email}"
        if security.too_many_attempts(key):
            return render_template("admin/login.html", email=email, error="Too many tries. Please wait a few minutes and try again."), 429
        user = fetch_one("SELECT id, full_name, email, password_hash, role, is_active FROM users WHERE email = %s", (email,))
        ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, pw)
        if user and ok and user["is_active"] and user["role"] == "admin":
            security.clear_attempts(key)
            if current_app.config["ADMIN_2FA"]:
                # Step 1 of 2: the password was right. Send a 6-digit code to the admin's email. NOT logged in yet.
                otp_helpers.remember_pending(session, PENDING, user["id"], request.args.get("next"))
                problem = otp_helpers.send_code(user["id"], user["full_name"], user["email"], "admin_login")
                flash(problem or "We sent a 6-digit code to your email. Type it below to finish logging in.", "warning" if problem else "info")
                return redirect(url_for("admin.verify"))
            security.login_user(user["id"])
            return redirect(security.safe_next(request.args.get("next"), url_for("admin.dashboard")))
        security.record_failed_attempt(key)
        return render_template("admin/login.html", email=email, error="Email or password is incorrect."), 401
    return render_template("admin/login.html", email=email, error=error)


def _pending_admin():
    pending = otp_helpers.read_pending(session, PENDING)
    if not pending:
        return None, None
    user = fetch_one("SELECT id, full_name, email, role, is_active FROM users WHERE id = %s", (pending["uid"],))
    if not user or not user["is_active"] or user["role"] != "admin":
        session.pop(PENDING, None)
        return None, None
    return user, pending


@bp.route("/verify", methods=["GET", "POST"])
def verify():
    """Step 2 of 2 of the admin login: type the 6-digit code from the email."""
    if g.user and g.user["role"] == "admin":
        return redirect(url_for("admin.dashboard"))
    user, pending = _pending_admin()
    if not user:
        flash("Please log in with your password first.", "info")
        return redirect(url_for("admin.login"))
    otp = current_app.extensions["otp"]
    error = ""
    if request.method == "POST":
        result = otp.verify(user["id"], "admin_login", request.form.get("code"))
        if result.ok:
            target = security.safe_next(pending["next"], url_for("admin.dashboard"))
            security.login_user(user["id"])                       # only NOW is the admin logged in
            return redirect(target)
        error = result.message
    return render_template("admin/verify.html", masked=otp_helpers.mask_email(user["email"]), minutes=otp.minutes, error=error), (400 if error else 200)


@bp.route("/verify/resend", methods=["POST"])
def verify_resend():
    user, pending = _pending_admin()
    if not user:
        return redirect(url_for("admin.login"))
    problem = otp_helpers.send_code(user["id"], user["full_name"], user["email"], "admin_login")
    flash(problem or "We sent a new code. The old code no longer works.", "warning" if problem else "success")
    return redirect(url_for("admin.verify"))


@bp.route("/logout", methods=["POST"])
def logout():
    security.logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("admin.login"))


# ------------------------------------------------------------------ dashboard
@bp.route("/")
def dashboard():
    return render_template("admin/dashboard.html", d=svc.dashboard(parse_int(request.args.get("range"), 7)))


# ------------------------------------------------------------------ plants
@bp.route("/plants")
def plants():
    q = clean(request.args.get("q"), 60)
    category_id = parse_int(request.args.get("category"), None)
    availability = request.args.get("availability", "")
    sort = request.args.get("sort", "name-asc")
    rows = svc.search_plants(q, category_id, availability, sort)
    return render_template("admin/plants.html", plants=rows, categories=svc.list_categories(), q=q, category_id=category_id,
                           availability=availability, sort=sort, total=len(svc.search_plants()))


def _plant_form(plant=None):
    values = {"name": "", "category_id": "", "price": "", "stock": "0", "description": "", "is_available": True}
    if plant:
        values = {"name": plant["name"], "category_id": plant["category_id"], "price": plant["price"], "stock": plant["stock_quantity"],
                  "description": plant["description"], "is_available": bool(plant["is_available"])}
    errors = {}
    if request.method == "POST":
        values = {"name": request.form.get("name", ""), "category_id": parse_int(request.form.get("category_id"), ""),
                  "price": request.form.get("price", ""), "stock": request.form.get("stock", ""),
                  "description": request.form.get("description", ""), "is_available": bool(request.form.get("is_available"))}
        try:
            plant_id = svc.save_plant(request.form, request.files.get("image"), g.user["id"], plant["id"] if plant else None)
        except FormError as exc:
            errors = exc.errors
        except AdminError as exc:
            flash(str(exc), "error")
            return redirect(url_for("admin.plants"))
        else:
            flash("Plant updated." if plant else "Plant added. It now shows on the customer website.", "success")
            return redirect(url_for("admin.plants"))
    return render_template("admin/plant_form.html", plant=plant, values=values, errors=errors, categories=svc.list_categories()), (400 if errors else 200)


@bp.route("/plants/new", methods=["GET", "POST"])
def plant_new():
    return _plant_form(None)


@bp.route("/plants/<int:plant_id>/edit", methods=["GET", "POST"])
def plant_edit(plant_id):
    plant = svc.get_plant(plant_id)
    if not plant:
        abort(404)
    return _plant_form(plant)


@bp.route("/plants/<int:plant_id>/toggle", methods=["POST"])
def plant_toggle(plant_id):
    available = request.form.get("available") == "1"
    try:
        svc.set_plant_available(plant_id, available)
        flash("Plant is now available to customers." if available else "Plant is now hidden from customers.", "success")
    except AdminError as exc:
        flash(str(exc), "error")
    return redirect(_back(url_for("admin.plants")))


@bp.route("/plants/<int:plant_id>/delete", methods=["POST"])
def plant_delete(plant_id):
    try:
        name = svc.delete_plant(plant_id)
        flash(f"Deleted {name}.", "success")
    except AdminError as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin.plants"))


# ------------------------------------------------------------------ orders
@bp.route("/orders")
def orders():
    q, status = clean(request.args.get("q"), 60), request.args.get("status", "")
    date_from, date_to = request.args.get("from", ""), request.args.get("to", "")
    rows, pager, error = svc.search_orders(q, status, date_from, date_to, parse_int(request.args.get("page"), 1))
    return render_template("admin/orders.html", orders=rows, pager=pager, error=error, q=q, status=status,
                           date_from=date_from, date_to=date_to, statuses=svc.STATUSES)


@bp.route("/orders/<int:order_id>")
def order_detail(order_id):
    order = svc.get_order(order_id)
    if not order:
        abort(404)
    return render_template("admin/order_detail.html", order=order, next_statuses=svc.TRANSITIONS[order["status"]])


@bp.route("/orders/<int:order_id>/status", methods=["POST"])
def order_status(order_id):
    try:
        svc.set_order_status(order_id, request.form.get("status", ""), g.user["id"])
        order = svc.get_order(order_id)
        current_app.extensions["notifier"].order_status(order, order["customer"], order["email"])      # tell the customer
        flash(f"Order GG-{order_id} is now {request.form.get('status')}. The customer was emailed.", "success")
    except AdminError as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin.order_detail", order_id=order_id))


# ------------------------------------------------------------------ inventory
@bp.route("/inventory")
def inventory():
    q, level, sort = clean(request.args.get("q"), 60), request.args.get("level", ""), request.args.get("sort", "name-asc")
    plant_id, mtype = parse_int(request.args.get("plant"), None), request.args.get("type", "")
    history, pager = svc.movement_history(plant_id, mtype, parse_int(request.args.get("page"), 1))
    return render_template("admin/inventory.html", rows=svc.inventory_rows(q, level, sort), summary=svc.inventory_summary(), q=q, level=level,
                           sort=sort, history=history, pager=pager, hist_plant=plant_id, hist_type=mtype,
                           all_plants=svc.search_plants(), movement_types=svc.MOVEMENT_TYPES)


@bp.route("/inventory/<int:plant_id>/adjust", methods=["GET", "POST"])
def inventory_adjust(plant_id):
    plant = svc.get_plant(plant_id)
    if not plant:
        abort(404)
    values, errors = {"mode": "restock", "qty": "", "note": ""}, {}
    if request.method == "POST":
        values = {"mode": request.form.get("mode", ""), "qty": request.form.get("qty", ""), "note": request.form.get("note", "")}
        try:
            after = svc.adjust_stock(plant_id, values["mode"], values["qty"], values["note"], g.user["id"])
        except FormError as exc:
            errors = exc.errors
        except AdminError as exc:
            errors = {"qty": str(exc)}
        else:
            flash(f"Stock updated. {plant['name']} now has {after}.", "success")
            return redirect(url_for("admin.inventory"))
    return render_template("admin/adjust.html", plant=plant, values=values, errors=errors), (400 if errors else 200)


# ------------------------------------------------------------------ customers
@bp.route("/customers")
def customers():
    q, status, sort = clean(request.args.get("q"), 60), request.args.get("status", ""), request.args.get("sort", "name-asc")
    rows, pager = svc.search_customers(q, status, sort, parse_int(request.args.get("page"), 1))
    return render_template("admin/customers.html", customers=rows, pager=pager, summary=svc.customer_summary(), q=q, status=status, sort=sort)


@bp.route("/customers/<int:user_id>")
def customer_detail(user_id):
    customer = svc.get_customer(user_id)
    if not customer:
        abort(404)
    return render_template("admin/customer_detail.html", c=customer)


@bp.route("/customers/<int:user_id>/toggle", methods=["POST"])
def customer_toggle(user_id):
    active = request.form.get("active") == "1"
    try:
        name = svc.set_customer_active(user_id, active)
        flash(f"{name}'s account was {'reactivated' if active else 'deactivated'}.", "success")
    except AdminError as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin.customer_detail", user_id=user_id))