"""Home, plant catalog, plant details, cart, and checkout."""
from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for

import security
import services
from services import OrderRejected
from validators import clean, parse_int, validate_contact

bp = Blueprint("shop", __name__)


@bp.route("/")
def home():
    return render_template("customer/index.html", featured=services.featured_plants(4))


@bp.route("/plants")
def plants():
    q = clean(request.args.get("q"), 60)
    categories = services.list_categories()
    category = request.args.get("category", "")
    if category not in [c["name"] for c in categories]:
        category = ""
    availability = request.args.get("availability", "")
    availability = availability if availability in ("in", "out") else ""
    sort = request.args.get("sort", "")
    sort = sort if sort in services.SORTS else ""
    items = services.list_plants(q, category, availability, sort)
    return render_template("customer/plants.html", plants=items, categories=categories, q=q, category=category,
                           availability=availability, sort=sort, total=len(services.list_plants()))


@bp.route("/plants/<int:plant_id>")
def plant_detail(plant_id):
    plant = services.get_plant(plant_id)
    if not plant:
        abort(404)
    return render_template("customer/plant.html", plant=plant)


# ------------------------------------------------------------------ cart
@bp.route("/cart")
def cart():
    lines, cleaned, notes = services.cart_lines(services.read_cart(session))
    services.save_cart(session, cleaned)
    for n in notes:
        flash(n, "warning")
    return render_template("customer/cart.html", lines=lines, subtotal=services.cart_subtotal(lines),
                           blocked=any(l["out"] for l in lines))


@bp.route("/cart/add", methods=["POST"])
def cart_add():
    plant = services.get_plant(parse_int(request.form.get("plant_id"), -1))
    qty = parse_int(request.form.get("qty", "1"), 0)
    back = security.safe_next(request.form.get("next"), url_for("shop.plants"))
    if not plant or qty is None or qty < 1:
        flash("Sorry, we could not add that plant.", "error")
        return redirect(back)
    limit = services.max_qty(plant["stock_quantity"])
    if limit < 1:
        flash(f"Sorry, {plant['name']} is out of stock.", "error")
        return redirect(back)
    cart = services.read_cart(session)
    have = cart.get(plant["id"], 0)
    if have >= limit:
        flash(f"Only {limit} of {plant['name']} available per order.", "warning")
    else:
        cart[plant["id"]] = min(limit, have + qty)
        services.save_cart(session, cart)
        flash(f"Added {plant['name']} to your cart.", "success")
    return redirect(url_for("shop.checkout") if request.form.get("buy_now") else back)


@bp.route("/cart/update", methods=["POST"])
def cart_update():
    plant = services.get_plant(parse_int(request.form.get("plant_id"), -1))
    cart = services.read_cart(session)
    if plant and plant["id"] in cart:
        wanted = parse_int(request.form.get("qty"), 1)
        limit = max(1, services.max_qty(plant["stock_quantity"]))
        if wanted > limit:
            flash(f"Only {limit} of {plant['name']} available per order.", "warning")
        cart[plant["id"]] = min(limit, max(1, wanted))
        services.save_cart(session, cart)
    return redirect(url_for("shop.cart"))


@bp.route("/cart/remove", methods=["POST"])
def cart_remove():
    cart = services.read_cart(session)
    cart.pop(parse_int(request.form.get("plant_id"), -1), None)
    services.save_cart(session, cart)
    flash("Removed from your cart.", "info")
    return redirect(url_for("shop.cart"))


@bp.route("/cart/clear", methods=["POST"])
def cart_clear():
    session.pop("cart", None)
    return redirect(url_for("shop.cart"))


# ------------------------------------------------------------------ checkout
@bp.route("/checkout", methods=["GET", "POST"])
@security.customer_required
def checkout():
    raw_cart = services.read_cart(session)                      # exactly what the customer put in the cart
    lines, cleaned, notes = services.cart_lines(raw_cart)       # the same cart checked against today's stock
    if request.method == "GET":
        services.save_cart(session, cleaned)                    # showing the page may fix the cart, but the customer sees a warning first
        for n in notes:
            flash(n, "warning")
    if not lines:
        flash("Your cart is empty. Add a plant before checking out.", "info")
        return redirect(url_for("shop.plants"))
    u = g.user
    values = {"name": u["full_name"], "phone": u["phone"] or "", "address": u["address"] or "",
              "city": u["city"] or "Bay", "province": u["province"] or "Laguna", "notes": "", "fulfillment": "pickup"}
    errors, problems = {}, []
    if request.method == "POST":
        values = {"name": clean(request.form.get("name"), 80), "phone": clean(request.form.get("phone"), 20),
                  "address": clean(request.form.get("address"), 120), "city": clean(request.form.get("city"), 60),
                  "province": clean(request.form.get("province"), 60), "notes": clean(request.form.get("notes"), 200),
                  "fulfillment": request.form.get("fulfillment", "")}
        errors = validate_contact(values)               # field-by-field messages shown next to the inputs
        if values["fulfillment"] not in ("pickup", "delivery"):
            problems.append("Choose pickup or delivery.")
        if not errors and not problems:
            try:
                order_id = services.place_order(u, raw_cart, values)   # never silently change what the customer asked for
            except OrderRejected as exc:                # for example: not enough stock anymore
                problems = exc.errors
                if cleaned != raw_cart:                  # fix the cart so the customer can review it and try again
                    services.save_cart(session, cleaned)
                    problems.append("We updated your cart to match what is in stock. Please check the summary and place your order again.")
            else:
                session.pop("cart", None)
                current_app.extensions["notifier"].order_placed(services.get_user_order(u["id"], order_id), u["full_name"], u["email"])
                return redirect(url_for("account.confirmation", order_id=order_id))
    fee = current_app.config["DELIVERY_FEE"] if values["fulfillment"] == "delivery" else 0
    subtotal = services.cart_subtotal(lines)
    return render_template("customer/checkout.html", lines=lines, subtotal=subtotal, fee=fee, total=subtotal + fee,
                           values=values, errors=errors, problems=problems), (400 if (errors or problems) and request.method == "POST" else 200)