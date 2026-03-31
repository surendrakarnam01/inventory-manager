import os
from datetime import datetime
from decimal import Decimal

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# -----------------------------
# Configuration
# -----------------------------

basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "inventory.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# NOTE: After changing the database schema (e.g., adding columns like `unit`),
# delete the existing `inventory.db` file so SQLite recreates it with the new columns.
#
# You asked to delete `inventory.db` before running again for this update.

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# -----------------------------
# Database Models
# -----------------------------


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    products = db.relationship("Product", backref="user", lazy=True)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(120), nullable=False)
    # `category` is stored as a predefined string (no enum needed).
    unit = db.Column(db.String(20), nullable=False)  # e.g. kg, gm, litre, ml, pieces, dozen, packet
    price = db.Column(db.Numeric(10, 2), nullable=False, default=Decimal("0.00"))
    quantity = db.Column(db.Integer, nullable=False, default=0)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


@app.context_processor
def inject_globals():
    return {"current_year": datetime.utcnow().year}


# -----------------------------
# Public Pages
# -----------------------------


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        message = (request.form.get("message") or "").strip()

        if not name or not email or not message:
            flash("Please fill out name, email, and message.", "danger")
        else:
            # No email sending required; just acknowledge the request.
            flash("Thanks for reaching out! Your message has been received.", "success")
            return redirect(url_for("contact"))

    return render_template("contact.html")


# -----------------------------
# Authentication
# -----------------------------


@app.get("/register")
def register():
    return render_template("register.html")


@app.post("/register")
def register_post():
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if not username or not email or not password or not confirm_password:
        flash("All fields are required.", "danger")
        return render_template("register.html")

    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return render_template("register.html")

    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()
    if existing_user:
        if existing_user.username == username:
            flash("Username already exists. Please choose another.", "danger")
        else:
            flash("Email already exists. Please use a different email.", "danger")
        return render_template("register.html")

    password_hash = generate_password_hash(password)
    user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    flash("Registration successful. Please log in.", "success")
    return redirect(url_for("login"))


@app.get("/login")
def login():
    return render_template("login.html")


@app.post("/login")
def login_post():
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    if not email or not password:
        flash("Email and password are required.", "danger")
        return render_template("login.html")

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        flash("Invalid email or password.", "danger")
        return render_template("login.html")

    login_user(user)
    flash("Welcome back! Your dashboard is ready.", "success")
    return redirect(url_for("dashboard"))


@app.get("/logout")
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


# -----------------------------
# Password reset
# -----------------------------


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()

        if not email:
            flash("Please enter your email address.", "danger")
            return render_template("forgot_password.html")

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with this email.", "danger")
            return render_template("forgot_password.html")

        return redirect(url_for("reset_password", user_id=user.id))

    return render_template("forgot_password.html")


@app.route("/reset-password/<int:user_id>", methods=["GET", "POST"])
def reset_password(user_id: int):
    user = User.query.get(user_id)
    if not user:
        flash("Account not found.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not new_password or not confirm_password:
            flash("Please enter and confirm your new password.", "danger")
            return render_template("reset_password.html", user=user)

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", user=user)

        user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        flash("Password updated successfully.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", user=user)


# -----------------------------
# Protected Inventory Routes
# -----------------------------


@app.get("/dashboard")
@login_required
def dashboard():
    products = Product.query.filter_by(user_id=current_user.id).order_by(Product.created_at.desc())

    total_products = products.count()
    low_stock_count = products.filter(Product.quantity <= 1).count()
    total_categories = (
        db.session.query(db.func.count(db.func.distinct(Product.category)))
        .filter(Product.user_id == current_user.id)
        .scalar()
        or 0
    )

    return render_template(
        "dashboard.html",
        products=products,
        total_products=total_products,
        low_stock_count=low_stock_count,
        total_categories=total_categories,
    )


@app.route("/add", methods=["GET", "POST"])
@login_required
def add_product():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        category = (request.form.get("category") or "").strip()
        unit = request.form["unit"]
        description = (request.form.get("description") or "").strip()
        price_raw = (request.form.get("price") or "").strip()
        quantity_raw = (request.form.get("quantity") or "").strip()

        error = None
        if not name or not category or not unit:
            error = "Name, category, and unit are required."

        try:
            price = Decimal(price_raw) if price_raw else Decimal("0.00")
            if price < 0:
                error = "Price cannot be negative."
        except Exception:
            error = "Please enter a valid price."

        try:
            quantity = int(quantity_raw) if quantity_raw else 0
            if quantity < 0:
                error = "Quantity cannot be negative."
        except Exception:
            error = "Please enter a valid quantity."

        if error:
            flash(error, "danger")
            return render_template("add.html")

        product = Product(
            name=name,
            category=category,
            unit=unit,
            price=price,
            quantity=quantity,
            description=description if description else None,
            user_id=current_user.id,
        )
        db.session.add(product)
        db.session.commit()

        flash("Product added successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("add.html")


@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_product(id: int):
    product = Product.query.filter_by(id=id, user_id=current_user.id).first()
    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        category = (request.form.get("category") or "").strip()
        unit = request.form["unit"]
        description = (request.form.get("description") or "").strip()
        price_raw = (request.form.get("price") or "").strip()
        quantity_raw = (request.form.get("quantity") or "").strip()

        error = None
        if not name or not category or not unit:
            error = "Name, category, and unit are required."

        try:
            price = Decimal(price_raw) if price_raw else Decimal("0.00")
            if price < 0:
                error = "Price cannot be negative."
        except Exception:
            error = "Please enter a valid price."

        try:
            quantity = int(quantity_raw) if quantity_raw else 0
            if quantity < 0:
                error = "Quantity cannot be negative."
        except Exception:
            error = "Please enter a valid quantity."

        if error:
            flash(error, "danger")
            return render_template("edit.html", product=product)

        product.name = name
        product.category = category
        product.unit = request.form["unit"]
        product.price = price
        product.quantity = quantity
        product.description = description if description else None
        db.session.commit()

        flash("Product updated successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit.html", product=product)


@app.post("/delete/<int:id>")
@login_required
def delete_product(id: int):
    product = Product.query.filter_by(id=id, user_id=current_user.id).first()
    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for("dashboard"))

    db.session.delete(product)
    db.session.commit()
    flash("Product deleted successfully.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

if __name__ == "__main__":
    app.run(debug=True)

