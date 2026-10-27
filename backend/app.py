from __future__ import annotations

import hashlib
import html
import hmac
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Iterator, TypedDict
from urllib.parse import parse_qs


PROJECT_PATH = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_PATH / "accounts.sqlite3"
LEGACY_STORE_PATH = PROJECT_PATH / "auth.json"
FRONTEND_PATH = PROJECT_PATH / "frontend"
ADMIN_BOOTSTRAP_EMAIL = "p.hour@gmail.com"
SESSION_COOKIE = "auth_session"
SESSION_LIFETIME = 7 * 24 * 60 * 60
PASSWORD_ITERATIONS = 310_000
MAX_REQUEST_SIZE = 16_384


class UserRecord(TypedDict):
    id: str
    name: str
    surname: str
    email: str
    password_hash: str
    created_at: int
    role: str
    points_balance: int


PAYMENT_METHODS = {
    "cash_on_delivery": "Cash on delivery",
    "bank_transfer": "Bank transfer",
    "pay_on_pickup": "Pay on pickup",
}
CATEGORY_SECTIONS = (
    ("Home & living", "Make your space feel like you."),
    ("Accessories", "Little essentials for wherever the day goes."),
    ("Stationery", "Good ideas deserve lovely paper."),
)


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def user_from_row(row: sqlite3.Row) -> UserRecord:
    return {
        "id": row["id"],
        "name": row["name"],
        "surname": row["surname"],
        "email": row["email"],
        "password_hash": row["password_hash"],
        "created_at": row["created_at"],
        "role": row["role"],
        "points_balance": row["points_balance"],
    }


def get_user_by_id(user_id: str) -> UserRecord | None:
    with database() as connection:
        row = connection.execute(
            "SELECT id, name, surname, email, password_hash, created_at, role, "
            "points_balance "
            "FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return user_from_row(row) if row else None


def get_user_by_email(email: str) -> UserRecord | None:
    with database() as connection:
        row = connection.execute(
            "SELECT id, name, surname, email, password_hash, created_at, role, "
            "points_balance "
            "FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    return user_from_row(row) if row else None


def create_user(user: UserRecord) -> bool:
    try:
        with database() as connection:
            connection.execute(
                "INSERT INTO users "
                "(id, name, surname, email, password_hash, created_at, role) "
                "VALUES (?, ?, ?, ?, ?, ?, 'customer')",
                (
                    user["id"],
                    user["name"],
                    user["surname"],
                    user["email"],
                    user["password_hash"],
                    user["created_at"],
                ),
            )
    except sqlite3.IntegrityError:
        return False
    return True


def get_session(token_hash: str, now: int) -> sqlite3.Row | None:
    with database() as connection:
        return connection.execute(
            "SELECT token_hash, csrf_token, user_id, expires_at "
            "FROM sessions WHERE token_hash = ? AND expires_at > ?",
            (token_hash, now),
        ).fetchone()


def create_session(
    token_hash: str,
    csrf_token: str,
    user_id: str | None,
    expires_at: int,
) -> None:
    with database() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE expires_at <= ?",
            (int(time.time()),),
        )
        connection.execute(
            "INSERT INTO sessions (token_hash, csrf_token, user_id, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token_hash, csrf_token, user_id, expires_at),
        )


def delete_session(token_hash: str) -> None:
    with database() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (token_hash,),
        )


def get_products() -> list[sqlite3.Row]:
    with database() as connection:
        return connection.execute(
            "SELECT id, name, category, description, price_cents, stock "
            "FROM products ORDER BY name"
        ).fetchall()


def get_cart_items(user_id: str) -> list[sqlite3.Row]:
    with database() as connection:
        return connection.execute(
            "SELECT p.id, p.name, p.price_cents, p.stock, c.quantity, "
            "(p.price_cents * c.quantity) AS line_total "
            "FROM cart_items c JOIN products p ON p.id = c.product_id "
            "WHERE c.user_id = ? ORDER BY p.name",
            (user_id,),
        ).fetchall()


def get_customer_interests(user_id: str) -> list[str]:
    with database() as connection:
        rows = connection.execute(
            "SELECT category, SUM(quantity) AS interest FROM ("
            "SELECT p.category, c.quantity FROM cart_items c "
            "JOIN products p ON p.id = c.product_id WHERE c.user_id = ? "
            "UNION ALL "
            "SELECT p.category, oi.quantity FROM order_items oi "
            "JOIN orders o ON o.id = oi.order_id "
            "JOIN products p ON p.id = oi.product_id WHERE o.user_id = ?"
            ") GROUP BY category ORDER BY interest DESC, category",
            (user_id, user_id),
        ).fetchall()
    return [row["category"] for row in rows]


def get_recommended_products(
    user_id: str, interests: list[str]
) -> list[sqlite3.Row]:
    preferred_categories = interests or ["Home & living", "Accessories"]
    with database() as connection:
        placeholders = ", ".join("?" for _ in preferred_categories)
        return connection.execute(
            "SELECT p.id, p.name, p.category, p.description, p.price_cents, p.stock "
            "FROM products p WHERE p.category IN (" + placeholders + ") "
            "AND p.stock > 0 AND NOT EXISTS ("
            "SELECT 1 FROM cart_items c WHERE c.user_id = ? AND c.product_id = p.id"
            ") ORDER BY p.name LIMIT 4",
            (*preferred_categories, user_id),
        ).fetchall()


def add_to_cart(user_id: str, product_id: str, quantity: int) -> str | None:
    with database() as connection:
        product = connection.execute(
            "SELECT stock FROM products WHERE id = ?", (product_id,)
        ).fetchone()
        if product is None:
            return "That product is no longer available."
        current = connection.execute(
            "SELECT quantity FROM cart_items WHERE user_id = ? AND product_id = ?",
            (user_id, product_id),
        ).fetchone()
        total_quantity = quantity + (current["quantity"] if current else 0)
        if quantity < 1 or total_quantity > product["stock"]:
            return "The selected quantity is not available."
        connection.execute(
            "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id, product_id) DO UPDATE SET quantity = excluded.quantity",
            (user_id, product_id, total_quantity),
        )
    return None


def place_order(
    user_id: str, payment_method: str
) -> tuple[str | None, str | None]:
    if payment_method not in PAYMENT_METHODS:
        return None, "Select a valid payment method."

    with database() as connection:
        items = connection.execute(
            "SELECT p.id, p.name, p.price_cents, p.stock, c.quantity "
            "FROM cart_items c JOIN products p ON p.id = c.product_id "
            "WHERE c.user_id = ?",
            (user_id,),
        ).fetchall()
        if not items:
            return None, "Your cart is empty."
        if any(item["quantity"] > item["stock"] for item in items):
            return None, "Some items are no longer available in the requested quantity."

        order_id = "YL-" + secrets.token_hex(6).upper()
        total_cents = sum(
            item["price_cents"] * item["quantity"] for item in items
        )
        points_awarded = total_cents // 100
        connection.execute(
            "INSERT INTO orders "
            "(id, user_id, total_cents, status, created_at, payment_method, points_awarded) "
            "VALUES (?, ?, ?, 'New', ?, ?, ?)",
            (
                order_id, user_id, total_cents, int(time.time()),
                payment_method, points_awarded,
            ),
        )
        connection.executemany(
            "INSERT INTO order_items "
            "(order_id, product_id, product_name, quantity, unit_price_cents) "
            "VALUES (?, ?, ?, ?, ?)",
            [
                (
                    order_id,
                    item["id"],
                    item["name"],
                    item["quantity"],
                    item["price_cents"],
                )
                for item in items
            ],
        )
        connection.executemany(
            "UPDATE products SET stock = stock - ? WHERE id = ?",
            [(item["quantity"], item["id"]) for item in items],
        )
        connection.execute(
            "UPDATE users SET points_balance = points_balance + ? WHERE id = ?",
            (points_awarded, user_id),
        )
        connection.execute("DELETE FROM cart_items WHERE user_id = ?", (user_id,))
    return order_id, None


def initialize_store() -> None:
    with database() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                surname TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'customer',
                points_balance INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expires_at_idx
                ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS products (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
                stock INTEGER NOT NULL CHECK (stock >= 0)
            );
            CREATE TABLE IF NOT EXISTS cart_items (
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                product_id TEXT NOT NULL REFERENCES products(id),
                quantity INTEGER NOT NULL CHECK (quantity > 0),
                PRIMARY KEY (user_id, product_id)
            );
            CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                total_cents INTEGER NOT NULL CHECK (total_cents >= 0),
                status TEXT NOT NULL DEFAULT 'New',
                created_at INTEGER NOT NULL,
                payment_method TEXT NOT NULL DEFAULT 'cash_on_delivery',
                points_awarded INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS order_items (
                order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
                product_id TEXT NOT NULL REFERENCES products(id),
                product_name TEXT NOT NULL,
                quantity INTEGER NOT NULL CHECK (quantity > 0),
                unit_price_cents INTEGER NOT NULL CHECK (unit_price_cents >= 0),
                PRIMARY KEY (order_id, product_id)
            );
            """
        )
        user_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(users)")
        }
        if "role" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'customer'"
            )
        if "points_balance" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN points_balance INTEGER NOT NULL DEFAULT 0"
            )

        order_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(orders)")
        }
        if "payment_method" not in order_columns:
            connection.execute(
                "ALTER TABLE orders ADD COLUMN payment_method TEXT NOT NULL "
                "DEFAULT 'cash_on_delivery'"
            )
        if "points_awarded" not in order_columns:
            connection.execute(
                "ALTER TABLE orders ADD COLUMN points_awarded INTEGER NOT NULL DEFAULT 0"
            )

        connection.executemany(
            "INSERT OR IGNORE INTO products "
            "(id, name, category, description, price_cents, stock) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("mug", "Sunday ceramics mug", "Home & living",
                 "Hand-finished stoneware for slow mornings.", 2500, 100),
                ("tote", "Linen market tote", "Accessories",
                 "A sturdy everyday tote made from natural linen.", 3200, 100),
                ("candles", "Coastline candle set", "Home & living",
                 "A set of two candles inspired by the coast.", 3800, 100),
                ("journal", "Daily notes journal", "Stationery",
                 "A cloth-bound journal for plans, lists, and ideas.", 1800, 100),
                ("tea-towel", "Sunday tea towel", "Home & living",
                 "Soft cotton with a cheerful, everyday print.", 1600, 100),
                ("planter", "Little sun planter", "Home & living",
                 "A bright ceramic home for your favorite small plants.", 2900, 100),
                ("soap", "Citrus grove hand soap", "Bath & body",
                 "A refreshing botanical hand wash with citrus notes.", 1400, 100),
                ("coasters", "Terrazzo coaster set", "Home & living",
                 "Four colorful coasters to protect your table.", 2200, 100),
                ("pouch", "Everyday zip pouch", "Accessories",
                 "A handy lined pouch for small essentials.", 1900, 100),
                ("vase", "Sunday bud vase", "Home & living",
                 "A sculptural little vase for fresh-picked stems.", 3400, 100),
                ("notecards", "Bright day notecards", "Stationery",
                 "A set of eight illustrated cards for thoughtful notes.", 1200, 100),
                ("scarf", "Soft morning scarf", "Accessories",
                 "A light, versatile scarf in a warm sunny palette.", 4200, 100),
                ("tray", "Pebble catchall tray", "Home & living",
                 "A small handmade tray for jewelry and everyday finds.", 2700, 100),
                ("gift-set", "The little joys gift set", "Gift sets",
                 "A ready-to-gift pairing of a candle and notecard set.", 4600, 100),
            ],
        )

        imported = connection.execute(
            "SELECT 1 FROM app_metadata WHERE key = 'legacy_json_imported'"
        ).fetchone()
        if not imported and LEGACY_STORE_PATH.exists():
            with LEGACY_STORE_PATH.open("r", encoding="utf-8") as store_file:
                legacy_store = json.load(store_file)
            if (
                not isinstance(legacy_store, dict)
                or legacy_store.get("version") != 1
                or not isinstance(legacy_store.get("users"), list)
                or not isinstance(legacy_store.get("sessions"), list)
            ):
                raise ValueError(f"Invalid account data format in {LEGACY_STORE_PATH}")
            users = legacy_store["users"]
            sessions = legacy_store["sessions"]
            if any(
                not isinstance(user, dict)
                or any(
                    not isinstance(user.get(field), str)
                    for field in ("id", "name", "surname", "email", "password_hash")
                )
                or not isinstance(user.get("created_at"), int)
                for user in users
            ) or any(
                not isinstance(session, dict)
                or any(
                    not isinstance(session.get(field), str)
                    for field in ("token_hash", "csrf_token")
                )
                or (
                    session.get("user_id") is not None
                    and not isinstance(session.get("user_id"), str)
                )
                or not isinstance(session.get("expires_at"), int)
                for session in sessions
            ):
                raise ValueError(f"Invalid account record in {LEGACY_STORE_PATH}")

            connection.executemany(
                "INSERT INTO users "
                "(id, name, surname, email, password_hash, created_at, role) "
                "VALUES (?, ?, ?, ?, ?, ?, 'customer')",
                [
                    (
                        user["id"],
                        user["name"],
                        user["surname"],
                        user["email"],
                        user["password_hash"],
                        user["created_at"],
                    )
                    for user in users
                ],
            )
            now = int(time.time())
            connection.executemany(
                "INSERT INTO sessions "
                "(token_hash, csrf_token, user_id, expires_at) VALUES (?, ?, ?, ?)",
                [
                    (
                        session["token_hash"],
                        session["csrf_token"],
                        session["user_id"],
                        session["expires_at"],
                    )
                    for session in sessions
                    if session["expires_at"] > now
                ],
            )
            connection.execute(
                "INSERT INTO app_metadata (key, value) "
                "VALUES ('legacy_json_imported', '1')"
            )
        admin_migration = connection.execute(
            "SELECT 1 FROM app_metadata WHERE key = 'admin_role_migration_v1'"
        ).fetchone()
        if not admin_migration:
            connection.execute(
                "UPDATE users SET role = 'admin' WHERE lower(email) = lower(?)",
                (ADMIN_BOOTSTRAP_EMAIL,),
            )
            connection.execute(
                "INSERT INTO app_metadata (key, value) "
                "VALUES ('admin_role_migration_v1', '1')"
            )
        connection.execute("DELETE FROM sessions")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, expected_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(actual, expected)


DUMMY_PASSWORD_HASH = hash_password("not-a-real-user-password")


def escape(value: str) -> str:
    return html.escape(value, quote=True)


def render_template(template_name: str, **values: str) -> str:
    template_path = FRONTEND_PATH / template_name
    template = template_path.read_text(encoding="utf-8")
    for key, value in values.items():
        template = template.replace("{{" + key + "}}", value)
    return template


def page(title: str, content: str) -> bytes:
    return render_template(
        "base.html",
        title=escape(title),
        content=content,
    ).encode("utf-8")


def alert(message: str, kind: str = "danger") -> str:
    return render_template(
        "alert.html",
        kind=escape(kind),
        message=escape(message),
    )


def signup_page(csrf_token: str, message: str = "", values: dict[str, str] | None = None) -> bytes:
    values = values or {}
    notice = alert(message) if message else ""
    content = render_template(
        "signup.html",
        csrf_token=escape(csrf_token),
        notice=notice,
        name=escape(values.get("name", "")),
        surname=escape(values.get("surname", "")),
        email=escape(values.get("email", "")),
    )
    return page("Sign up", content)


def signin_page(csrf_token: str, message: str = "", email: str = "") -> bytes:
    notice = alert(message) if message else ""
    content = render_template(
        "signin.html",
        csrf_token=escape(csrf_token),
        notice=notice,
        email=escape(email),
    )
    return page("Sign in", content)


def money(amount_cents: int) -> str:
    return f"${amount_cents / 100:,.2f}"


def product_card(product: sqlite3.Row, csrf_token: str, prefix: str) -> str:
    product_id = escape(product["id"])
    stock = product["stock"]
    input_id = f"{prefix}-{product_id}"
    return (
        '<article class="store-product">'
        '<div class="product-art" aria-hidden="true">Y<span>.</span></div>'
        f'<p class="store-category">{escape(product["category"])}</p>'
        f'<h3>{escape(product["name"])}</h3>'
        f'<p class="store-description">{escape(product["description"])}</p>'
        f'<div class="store-product-foot"><strong>{money(product["price_cents"])}</strong>'
        '<form method="post" action="/cart/add">'
        f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
        f'<input type="hidden" name="product_id" value="{product_id}">'
        f'<label class="visually-hidden" for="{input_id}">'
        f'Quantity for {escape(product["name"])}</label>'
        f'<input id="{input_id}" name="quantity" type="number" min="1" '
        f'max="{stock}" value="1" aria-label="Quantity" '
        f'{"disabled" if stock == 0 else ""}>'
        f'<button type="submit" {"disabled" if stock == 0 else ""}>'
        f'{"Sold out" if stock == 0 else "Add to cart"}</button>'
        '</form></div></article>'
    )


def storefront_page(
    user: UserRecord,
    csrf_token: str,
    notice: str = "",
    notice_kind: str = "success",
) -> bytes:
    products = get_products()
    cart_items = get_cart_items(user["id"])
    cart_count = sum(item["quantity"] for item in cart_items)
    category_collections = []
    for index, (category, description) in enumerate(CATEGORY_SECTIONS):
        category_products = [
            product for product in products if product["category"] == category
        ]
        if not category_products:
            continue
        cards = "".join(
            product_card(product, csrf_token, f"category-{index}")
            for product in category_products
        )
        category_collections.append(
            f'<section class="category-shelf" id="category-{index}">'
            '<div class="store-section-heading">'
            f'<div><p class="store-eyebrow">EXPLORE A CATEGORY</p>'
            f'<h2>{escape(category)}</h2></div>'
            f'<p>{escape(description)}</p>'
            '</div>'
            f'<div class="category-product-row" aria-label="{escape(category)} products">'
            f'{cards}</div></section>'
        )

    interests = get_customer_interests(user["id"])
    recommendations = get_recommended_products(user["id"], interests)
    recommendation_cards = "".join(
        product_card(product, csrf_token, "recommended") for product in recommendations
    )
    if not recommendation_cards:
        recommendation_cards = (
            '<p class="empty-recommendations">You have explored everything in your '
            'favorite categories. Check back as the collection grows.</p>'
        )
    return render_template(
        "store.html",
        name=escape(user["name"]),
        csrf_token=escape(csrf_token),
        points_balance=str(user["points_balance"]),
        cart_count=str(cart_count),
        notice=alert(notice, notice_kind) if notice else "",
        category_collections="".join(category_collections),
        recommendation_cards=recommendation_cards,
        recommendation_note=(
            "Picked from categories in your cart and past orders."
            if interests
            else "Explore these favorites while we learn what you like."
        ),
    ).encode("utf-8")


def cart_page(
    user: UserRecord,
    csrf_token: str,
    notice: str = "",
    notice_kind: str = "warning",
) -> bytes:
    items = get_cart_items(user["id"])
    rows = []
    total_cents = 0
    cart_count = 0
    for item in items:
        total_cents += item["line_total"]
        cart_count += item["quantity"]
        rows.append(
            "<tr>"
            f'<td>{escape(item["name"])}</td>'
            f'<td>{item["quantity"]}</td>'
            f'<td>{money(item["price_cents"])}</td>'
            f'<td>{money(item["line_total"])}</td>'
            "</tr>"
        )
    payment_options = "".join(
        f'<option value="{escape(method)}">{escape(label)}</option>'
        for method, label in PAYMENT_METHODS.items()
    )
    return render_template(
        "cart.html",
        name=escape(user["name"]),
        csrf_token=escape(csrf_token),
        cart_count=str(cart_count),
        points_balance=str(user["points_balance"]),
        payment_options=payment_options,
        notice=alert(notice, notice_kind) if notice else "",
        cart_rows="".join(rows),
        cart_total=money(total_cents),
        cart_item_count=str(cart_count),
        cart_empty=(
            '<p class="empty-cart">Your cart is empty. '
            '<a href="/shop">Browse the store</a>.</p>'
            if not items else ""
        ),
        checkout_disabled="disabled" if not items else "",
    ).encode("utf-8")


def dashboard_page(user: UserRecord, csrf_token: str) -> bytes:
    with database() as connection:
        totals = connection.execute(
            "SELECT COUNT(*) AS order_count, COALESCE(SUM(total_cents), 0) AS revenue "
            "FROM orders"
        ).fetchone()
        customer_count = connection.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'customer'"
        ).fetchone()[0]
        product_count = connection.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        orders = connection.execute(
            "SELECT o.id, o.total_cents, o.status, o.created_at, "
            "o.payment_method, o.points_awarded, "
            "u.name, u.surname, u.email, "
            "GROUP_CONCAT(oi.product_name || ' × ' || oi.quantity, ', ') AS items "
            "FROM orders o JOIN users u ON u.id = o.user_id "
            "JOIN order_items oi ON oi.order_id = o.id "
            "GROUP BY o.id ORDER BY o.created_at DESC LIMIT 12"
        ).fetchall()
        customers = connection.execute(
            "SELECT name, surname, email, created_at, points_balance FROM users "
            "WHERE role = 'customer' ORDER BY created_at DESC LIMIT 8"
        ).fetchall()

    order_rows = "".join(
        "<tr>"
        f'<td><strong>{escape(order["id"])}</strong>'
        f'<small>{escape(time.strftime("%b %d, %Y %H:%M", time.localtime(order["created_at"])))}</small></td>'
        f'<td>{escape(order["name"] + " " + order["surname"])}'
        f'<small>{escape(order["email"])}</small></td>'
        f'<td>{escape(order["items"] or "")}</td>'
        f'<td>{money(order["total_cents"])}</td>'
        f'<td>{escape(PAYMENT_METHODS.get(order["payment_method"], "Unknown"))}'
        f'<small>{order["points_awarded"]} points earned</small></td>'
        f'<td><span class="order-status">{escape(order["status"])}</span></td>'
        "</tr>"
        for order in orders
    ) or '<tr><td colspan="6" class="empty-table">No customer orders yet.</td></tr>'
    customer_rows = "".join(
        "<tr>"
        f'<td>{escape(customer["name"] + " " + customer["surname"])}</td>'
        f'<td>{escape(customer["email"])}</td>'
        f'<td>{escape(time.strftime("%b %d, %Y", time.localtime(customer["created_at"])))}</td>'
        f'<td>{customer["points_balance"]}</td>'
        "</tr>"
        for customer in customers
    ) or '<tr><td colspan="4" class="empty-table">No customer accounts yet.</td></tr>'
    content = render_template(
        "home.html",
        csrf_token=escape(csrf_token),
        name=escape(user["name"]),
        initial=escape(user["name"][:1].upper()),
        order_count=str(totals["order_count"]),
        revenue=money(totals["revenue"]),
        customer_count=str(customer_count),
        product_count=str(product_count),
        order_rows=order_rows,
        customer_rows=customer_rows,
    )
    return content.encode("utf-8")


class AuthHandler(BaseHTTPRequestHandler):
    server_version = "AccountApp"

    def _session(self) -> tuple[str, str, str | None, bool]:
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get(SESSION_COOKIE)
        token = morsel.value if morsel else ""
        now = int(time.time())
        token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()

        if token:
            session = get_session(token_hash, now)
            if session:
                return token, session["csrf_token"], session["user_id"], False

        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        create_session(
            hashlib.sha256(token.encode("ascii")).hexdigest(),
            csrf_token,
            None,
            now + SESSION_LIFETIME,
        )
        return token, csrf_token, None, True

    def _csrf_matches(self, csrf_token: str, form: dict[str, list[str]]) -> bool:
        submitted = form.get("csrf_token", [""])[0]
        if not submitted or not submitted.isascii():
            return False
        return hmac.compare_digest(csrf_token, submitted)

    def _send(
        self,
        status: HTTPStatus,
        body: bytes = b"",
        *,
        token: str | None = None,
        clear_cookie: bool = False,
        content_type: str = "text/html; charset=utf-8",
        location: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        if token is not None:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; "
                f"Max-Age={SESSION_LIFETIME}",
            )
        elif clear_cookie:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            )
        if location:
            self.send_header("Location", location)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _redirect(
        self,
        location: str,
        token: str | None = None,
        *,
        clear_cookie: bool = False,
    ) -> None:
        self._send(
            HTTPStatus.SEE_OTHER,
            token=token,
            clear_cookie=clear_cookie,
            location=location,
        )

    def do_GET(self) -> None:
        path, _, query_string = self.path.partition("?")
        query = parse_qs(query_string, keep_blank_values=True)
        if path == "/style.css":
            stylesheet = (FRONTEND_PATH / "style.css").read_bytes()
            self._send(
                HTTPStatus.OK,
                stylesheet,
                content_type="text/css; charset=utf-8",
            )
            return

        token, csrf_token, user_id, is_new = self._session()

        if path == "/":
            if user_id is None:
                self._redirect("/signin", token if is_new else None)
                return
            user = get_user_by_id(user_id)
            if user is None:
                self._redirect("/signin", token if is_new else None)
                return
            self._redirect(
                "/account" if user["role"] == "admin" else "/shop",
                token if is_new else None,
            )
        elif path in ("/signup", "/signin"):
            if user_id is not None:
                user = get_user_by_id(user_id)
                if user is None:
                    self._redirect("/signin", token if is_new else None)
                    return
                self._redirect(
                    "/account" if user["role"] == "admin" else "/shop",
                    token if is_new else None,
                )
            elif path == "/signup":
                self._send(HTTPStatus.OK, signup_page(csrf_token), token=token if is_new else None)
            else:
                self._send(HTTPStatus.OK, signin_page(csrf_token), token=token if is_new else None)
        elif path == "/shop":
            user = get_user_by_id(user_id) if user_id else None
            if user is None:
                self._redirect("/signin", token if is_new else None)
                return
            if user["role"] == "admin":
                self._redirect("/account", token if is_new else None)
                return
            order_id = query.get("order", [""])[0]
            order_exists = False
            if re.fullmatch(r"YL-[A-F0-9]{12}", order_id):
                with database() as connection:
                    order_exists = connection.execute(
                        "SELECT 1 FROM orders WHERE id = ? AND user_id = ?",
                        (order_id, user["id"]),
                    ).fetchone() is not None
            notice = (
                f"Order {order_id} was received. The store team will contact you about payment and fulfillment."
                if order_exists
                else ""
            )
            self._send(
                HTTPStatus.OK,
                storefront_page(user, csrf_token, notice),
                token=token if is_new else None,
            )
        elif path == "/cart":
            user = get_user_by_id(user_id) if user_id else None
            if user is None:
                self._redirect("/signin", token if is_new else None)
                return
            if user["role"] == "admin":
                self._redirect("/account", token if is_new else None)
                return
            added_notice = (
                "Cart updated. Your items and new total are shown below."
                if query.get("added", [""])[0] == "1"
                else ""
            )
            self._send(
                HTTPStatus.OK,
                cart_page(user, csrf_token, added_notice, "success"),
                token=token if is_new else None,
            )
        elif path == "/account":
            if user_id is None:
                self._redirect("/signin", token if is_new else None)
                return
            user = get_user_by_id(user_id)
            if user is None:
                self._redirect("/signin", token if is_new else None)
                return
            if user["role"] != "admin":
                self._redirect("/shop", token if is_new else None)
                return
            self._send(
                HTTPStatus.OK,
                dashboard_page(user, csrf_token),
                token=token if is_new else None,
            )
        else:
            self._send(HTTPStatus.NOT_FOUND, page("Not found", alert("Page not found.")))

    def do_POST(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = MAX_REQUEST_SIZE + 1
        if content_length < 0 or content_length > MAX_REQUEST_SIZE:
            self._send(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                page("Request too large", alert("The submitted form is too large.")),
            )
            return

        body = self.rfile.read(content_length)
        form = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        token, csrf_token, user_id, is_new = self._session()
        if is_new or not self._csrf_matches(csrf_token, form):
            self._send(
                HTTPStatus.FORBIDDEN,
                page("Form expired", alert("This form has expired. Please reload and try again.")),
                token=token if is_new else None,
            )
            return

        path = self.path.split("?", 1)[0]
        if path == "/signup":
            self._signup(form, token)
        elif path == "/signin":
            self._signin(form, token)
        elif path == "/cart/add":
            user = get_user_by_id(user_id) if user_id else None
            if user is None or user["role"] != "customer":
                self._redirect("/signin")
                return
            product_id = form.get("product_id", [""])[0]
            try:
                quantity = int(form.get("quantity", ["0"])[0])
            except ValueError:
                quantity = 0
            error = add_to_cart(user["id"], product_id, quantity)
            if error:
                self._send(
                    HTTPStatus.BAD_REQUEST,
                    storefront_page(user, csrf_token, error, "danger"),
                )
                return
            self._redirect("/cart?added=1")
        elif path == "/checkout":
            user = get_user_by_id(user_id) if user_id else None
            if user is None or user["role"] != "customer":
                self._redirect("/signin")
                return
            payment_method = form.get("payment_method", [""])[0]
            order_id, error = place_order(user["id"], payment_method)
            if error:
                self._send(
                    HTTPStatus.BAD_REQUEST,
                    cart_page(user, csrf_token, error),
                )
                return
            self._redirect(f"/shop?order={order_id}")
        elif path == "/logout":
            if user_id is None:
                self._redirect("/signin")
                return
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
            delete_session(token_hash)
            self._redirect("/signin", clear_cookie=True)
        else:
            self._send(HTTPStatus.NOT_FOUND, page("Not found", alert("Page not found.")))

    def _signup(self, form: dict[str, list[str]], token: str) -> None:
        name = form.get("name", [""])[0].strip()
        surname = form.get("surname", [""])[0].strip()
        email = form.get("email", [""])[0].strip().lower()
        password = form.get("password", [""])[0]
        values = {"name": name, "surname": surname, "email": email}

        if (
            not name
            or len(name) > 80
            or not surname
            or len(surname) > 80
            or len(email) > 254
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
            or len(password) < 8
            or len(password) > 1024
        ):
            self._render_signup_error(
                token,
                "Check the fields and try again. Passwords must be at least 8 characters.",
                values,
            )
            return

        user_id = secrets.token_urlsafe(16)
        user: UserRecord = {
            "id": user_id,
            "name": name,
            "surname": surname,
            "email": email,
            "password_hash": hash_password(password),
            "created_at": int(time.time()),
            "role": "customer",
            "points_balance": 0,
        }
        if not create_user(user):
            self._render_signup_error(token, "An account with that email already exists.", values)
            return
        new_token = self._replace_session(token, user_id)
        self._redirect("/shop", new_token)

    def _render_signup_error(self, token: str, message: str, values: dict[str, str]) -> None:
        csrf_token = self._rotate_csrf(token)
        self._send(
            HTTPStatus.BAD_REQUEST,
            signup_page(csrf_token, message, values),
            token=token,
        )

    def _signin(self, form: dict[str, list[str]], token: str) -> None:
        email = form.get("email", [""])[0].strip().lower()
        password = form.get("password", [""])[0]
        user = get_user_by_email(email)

        stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
        password_is_valid = verify_password(password[:1024], stored_hash)
        if not user or not password_is_valid or len(password) > 1024:
            csrf_token = self._rotate_csrf(token)
            self._send(
                HTTPStatus.UNAUTHORIZED,
                signin_page(csrf_token, "Email or password is incorrect.", email),
                token=token,
            )
            return

        new_token = self._replace_session(token, user["id"])
        self._redirect(
            "/account" if user["role"] == "admin" else "/shop",
            new_token,
        )

    def _rotate_csrf(self, token: str) -> str:
        csrf_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with database() as connection:
            connection.execute(
                "UPDATE sessions SET csrf_token = ? WHERE token_hash = ?",
                (csrf_token, token_hash),
            )
        return csrf_token

    def _replace_session(self, old_token: str, user_id: str) -> str:
        new_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        old_hash = hashlib.sha256(old_token.encode("ascii")).hexdigest()
        with database() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (old_hash,),
            )
            connection.execute(
                "INSERT INTO sessions (token_hash, csrf_token, user_id, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    hashlib.sha256(new_token.encode("ascii")).hexdigest(),
                    csrf_token,
                    user_id,
                    int(time.time()) + SESSION_LIFETIME,
                ),
            )
        return new_token
