"""A customer's own orders, tracking, and profile. Every query is limited to the logged-in customer."""
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

import db
import security
import services
from validators import clean, normalize_phone, parse_order_code, validate_profile

bp = Blueprint("account", __name__)


@bp.route("/my-orders")
@security.customer_required
def my_orders():
    return render_template("customer/my_orders.html", orders=services.list_user_orders(g.user["id"]))


@bp.route("/orders/<int:order_id>")
@security.customer_required
def order_details(order_id):
    order = services.get_user_order(g.user["id"], order_id)
    if not order:
        abort(404)
    return render_template("customer/order_details.html", order=order)


@bp.route("/orders/<int:order_id>/confirmation")
@security.customer_required
def confirmation(order_id):
    order = services.get_user_order(g.user["id"], order_id)
    if not order:
        abort(404)
    return render_template("customer/confirmation.html", order=order)


@bp.route("/track")
@security.customer_required
def track():
    typed = clean(request.args.get("id"), 20)
    order, error = None, ""
    if request.args.get("id") is not None:
        number = parse_order_code(typed)
        if not typed:
            error = "Enter your order ID."
        elif number is None:
            error = "Order IDs look like GG-2001."
        else:
            order = services.get_user_order(g.user["id"], number)
            if not order:
                error = "We could not find that order in your account. Check the ID and try again."
    mine = db.fetch_all("SELECT id FROM orders WHERE user_id = %s ORDER BY id DESC", (g.user["id"],))
    return render_template("customer/track.html", typed=typed, order=order, error=error, my_ids=[m["id"] for m in mine])


@bp.route("/account", methods=["GET", "POST"])
@security.customer_required
def account():
    u = g.user
    values = {"name": u["full_name"], "phone": u["phone"] or "", "address": u["address"] or "",
              "city": u["city"] or "", "province": u["province"] or ""}
    errors = {}
    if request.method == "POST":
        values = {"name": clean(request.form.get("name"), 80), "phone": clean(request.form.get("phone"), 20),
                  "address": clean(request.form.get("address"), 120), "city": clean(request.form.get("city"), 60),
                  "province": clean(request.form.get("province"), 60)}
        errors = validate_profile(values)
        if not errors:
            with db.transaction() as cur:
                cur.execute("UPDATE users SET full_name = %s, phone = %s, address = %s, city = %s, province = %s WHERE id = %s",
                            (values["name"], normalize_phone(values["phone"]) or None, values["address"] or None,
                             values["city"] or None, values["province"] or None, u["id"]))
            flash("Your changes were saved.", "success")
            return redirect(url_for("account.account"))
    count = db.fetch_one("SELECT COUNT(*) AS n FROM orders WHERE user_id = %s", (u["id"],))["n"]
    return render_template("customer/account.html", values=values, errors=errors, order_count=count), (400 if errors else 200)
