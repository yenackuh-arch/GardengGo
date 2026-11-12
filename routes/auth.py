"""Customer register / login / logout."""
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import db
import otp as otp_helpers
import security
from db import fetch_one, transaction
from validators import clean, validate_email, validate_password

bp = Blueprint("auth", __name__)

# Used to spend the same time when the email does not exist, so attackers cannot tell which emails have accounts
_DUMMY_HASH = generate_password_hash("not-a-real-password")


def _is_duplicate(exc):
    return type(exc).__name__ == "IntegrityError"


PENDING = "pending_verify"          # session key: "this person is typing their email code (not logged in yet)"


def _begin_verification(user, next_url):
    """Sends a 6-digit code to the customer and sends them to the 'type your code' page. They are NOT logged in yet."""
    otp_helpers.remember_pending(session, PENDING, user["id"], next_url)
    return otp_helpers.send_code(user["id"], user["full_name"], user["email"], "verify_email")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("shop.home"))
    values, errors = {"name": "", "email": ""}, {}
    if request.method == "POST":
        values = {"name": clean(request.form.get("name"), 80), "email": clean(request.form.get("email"), 120).lower()}
        pw, cpw = request.form.get("password", ""), request.form.get("confirm_password", "")
        require = current_app.config["REQUIRE_EMAIL_VERIFICATION"]
        if not 2 <= len(values["name"]) <= 80:
            errors["name"] = "Enter your full name (2 to 80 characters)."
        if validate_email(values["email"]):
            errors["email"] = validate_email(values["email"])
        if validate_password(pw):
            errors["password"] = validate_password(pw)
        if pw != cpw:
            errors["confirm_password"] = "Passwords do not match."
        existing = None if errors.get("email") else fetch_one("SELECT id, role, email_verified FROM users WHERE email = %s", (values["email"],))
        # An email that was never confirmed does not belong to anyone yet, so a new sign-up may take it over
        # (only the real owner of the inbox can get the code). A confirmed email is always protected.
        takeover = bool(existing and require and existing["role"] == "customer" and not existing["email_verified"])
        if existing and not takeover:
            errors["email"] = "An account with this email already exists. Please log in."
        if not errors:
            try:
                with transaction() as cur:
                    if takeover:
                        cur.execute("UPDATE users SET full_name = %s, password_hash = %s WHERE id = %s",
                                    (values["name"], generate_password_hash(pw), existing["id"]))
                        user_id = existing["id"]
                    else:
                        cur.execute("INSERT INTO users (full_name, email, password_hash, role, email_verified) VALUES (%s, %s, %s, 'customer', %s)",
                                    (values["name"], values["email"], generate_password_hash(pw), 0 if require else 1))
                        user_id = cur.lastrowid
            except Exception as exc:                   # two people registering the same email at the same moment
                if not _is_duplicate(exc):
                    raise
                errors["email"] = "An account with this email already exists. Please log in."
            else:
                if require:
                    _begin_verification({"id": user_id, "full_name": values["name"], "email": values["email"]}, request.args.get("next"))
                    flash("We sent a 6-digit code to your email. Type it below to finish creating your account.", "info")
                    return redirect(url_for("auth.verify_email"))
                security.login_user(user_id)
                current_app.extensions["notifier"].welcome(values["name"], values["email"])
                flash("Welcome to GardenGo! Your account is ready.", "success")
                return redirect(security.safe_next(request.args.get("next"), url_for("shop.home")))
    return render_template("customer/register.html", values=values, errors=errors), (400 if errors else 200)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user and g.user["role"] == "customer":
        return redirect(security.safe_next(request.args.get("next"), url_for("shop.home")))
    email, error = "", ""
    if request.method == "POST":
        email = clean(request.form.get("email"), 120).lower()
        pw = request.form.get("password", "")
        key = f"{request.remote_addr}|{email}"
        if security.too_many_attempts(key):
            return render_template("customer/login.html", email=email, error="Too many tries. Please wait a few minutes and try again."), 429
        user = fetch_one("SELECT id, full_name, email, password_hash, role, is_active, email_verified FROM users WHERE email = %s", (email,))
        password_ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, pw)
        if user and password_ok and user["is_active"] and user["role"] == "customer":
            security.clear_attempts(key)
            if current_app.config["REQUIRE_EMAIL_VERIFICATION"] and not user["email_verified"]:
                problem = _begin_verification(user, request.args.get("next"))
                flash(problem or "Please confirm your email first. We sent you a new 6-digit code.", "warning" if problem else "info")
                return redirect(url_for("auth.verify_email"))
            security.login_user(user["id"])
            return redirect(security.safe_next(request.args.get("next"), url_for("shop.home")))
        security.record_failed_attempt(key)
        error = "Email or password is incorrect."        # same message for every kind of failure
        return render_template("customer/login.html", email=email, error=error), 401
    return render_template("customer/login.html", email=email, error=error)


# ------------------------------------------------------------------ confirm email with a 6-digit code
def _pending_customer():
    """The customer who is typing a code, or None (then the caller sends the visitor to the login page)."""
    pending = otp_helpers.read_pending(session, PENDING)
    if not pending:
        return None, None
    user = fetch_one("SELECT id, full_name, email, role, is_active, email_verified FROM users WHERE id = %s", (pending["uid"],))
    if not user or not user["is_active"] or user["role"] != "customer" or user["email_verified"]:
        session.pop(PENDING, None)
        return None, None
    return user, pending


@bp.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    user, pending = _pending_customer()
    if not user:
        flash("Please register or log in first.", "info")
        return redirect(url_for("auth.login"))
    otp = current_app.extensions["otp"]
    error = ""
    if request.method == "POST":
        result = otp.verify(user["id"], "verify_email", request.form.get("code"))
        if result.ok:
            with transaction() as cur:
                cur.execute("UPDATE users SET email_verified = 1 WHERE id = %s", (user["id"],))
            target = security.safe_next(pending["next"], url_for("shop.home"))
            security.login_user(user["id"])                       # only NOW is the customer logged in
            current_app.extensions["notifier"].welcome(user["full_name"], user["email"])
            flash("Your email is confirmed. Welcome to GardenGo!", "success")
            return redirect(target)
        error = result.message
    return render_template("customer/verify_email.html", masked=otp_helpers.mask_email(user["email"]), minutes=otp.minutes, error=error), (400 if error else 200)


@bp.route("/verify-email/resend", methods=["POST"])
def verify_email_resend():
    user, pending = _pending_customer()
    if not user:
        return redirect(url_for("auth.login"))
    problem = otp_helpers.send_code(user["id"], user["full_name"], user["email"], "verify_email")
    flash(problem or "We sent a new code. The old code no longer works.", "warning" if problem else "success")
    return redirect(url_for("auth.verify_email"))


@bp.route("/logout", methods=["POST"])
def logout():
    security.logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("shop.home"))


# ------------------------------------------------------------------ forgot / reset password
RESET_ANSWER = "If that email belongs to a GardenGo account, we sent a link to reset the password. Please check your inbox (and the spam folder)."


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    email, error = "", ""
    if request.method == "POST":
        email = clean(request.form.get("email"), 120).lower()
        key = f"forgot|{request.remote_addr}"
        if security.too_many_attempts(key):
            return render_template("customer/forgot_password.html", email=email, error="Too many requests. Please wait a few minutes and try again."), 429
        security.record_failed_attempt(key)                  # every request counts, so nobody can flood an inbox with emails
        error = validate_email(email)
        if not error:
            user = fetch_one("SELECT id, full_name, email, password_hash, role, is_active FROM users WHERE email = %s", (email,))
            if user and user["is_active"] and user["role"] == "customer":
                link = url_for("auth.reset_password", token=current_app.extensions["reset_tokens"].make(user), _external=True)
                current_app.extensions["notifier"].password_reset(user["full_name"], user["email"], link, current_app.config["RESET_LINK_MINUTES"])
            flash(RESET_ANSWER, "info")                      # the same answer whether or not the account exists
            return redirect(url_for("auth.login"))
    return render_template("customer/forgot_password.html", email=email, error=error), (400 if error else 200)


def _user_for_reset_token(token):
    tokens = current_app.extensions["reset_tokens"]
    parsed = tokens.read(token)
    if not parsed:
        return None
    user_id, fingerprint = parsed
    user = fetch_one("SELECT id, full_name, email, password_hash, role, is_active FROM users WHERE id = %s", (user_id,))
    if user and user["is_active"] and user["role"] == "customer" and tokens.matches(fingerprint, user):
        return user
    return None


@bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = _user_for_reset_token(token)
    if not user:
        return render_template("customer/reset_invalid.html"), 400
    errors = {}
    if request.method == "POST":
        pw, cpw = request.form.get("password", ""), request.form.get("confirm_password", "")
        if validate_password(pw):
            errors["password"] = validate_password(pw)
        elif check_password_hash(user["password_hash"], pw):
            errors["password"] = "Please choose a password you have not used before."
        if pw != cpw:
            errors["confirm_password"] = "Passwords do not match."
        if not errors:
            with transaction() as cur:
                cur.execute("UPDATE users SET password_hash = %s, email_verified = 1 WHERE id = %s", (generate_password_hash(pw), user["id"]))
            security.logout_user()
            current_app.extensions["notifier"].password_changed(user["full_name"], user["email"])
            flash("Your password was changed. You can log in now.", "success")
            return redirect(url_for("auth.login"))
    return render_template("customer/reset_password.html", errors=errors), (400 if errors else 200)