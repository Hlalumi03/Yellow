import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import app


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "accounts.sqlite3"
        self.legacy_path = Path(self.temp_dir.name) / "auth.json"
        self.database_patch = patch.object(app, "DATABASE_PATH", self.database_path)
        self.legacy_patch = patch.object(app, "LEGACY_STORE_PATH", self.legacy_path)
        self.database_patch.start()
        self.legacy_patch.start()
        self.addCleanup(self.database_patch.stop)
        self.addCleanup(self.legacy_patch.stop)
        self.addCleanup(self.temp_dir.cleanup)
        app.initialize_store()

    def create_user(self, email: str, user_id: str = "customer-1") -> app.UserRecord:
        user: app.UserRecord = {
            "id": user_id,
            "name": "Test",
            "surname": "Customer",
            "email": email,
            "password_hash": app.hash_password("correct horse battery staple"),
            "created_at": 1,
            "role": "customer",
            "points_balance": 0,
        }
        self.assertTrue(app.create_user(user))
        return user

    def test_customer_can_add_items_and_place_order(self) -> None:
        customer = self.create_user("customer@example.com")

        self.assertIsNone(app.add_to_cart(customer["id"], "mug", 2))
        order_id, error = app.place_order(customer["id"], "bank_transfer")

        self.assertIsNone(error)
        self.assertIsNotNone(order_id)
        with app.database() as connection:
            order = connection.execute(
                "SELECT user_id, total_cents, status, payment_method, points_awarded "
                "FROM orders WHERE id = ?",
                (order_id,),
            ).fetchone()
            stock = connection.execute(
                "SELECT stock FROM products WHERE id = 'mug'"
            ).fetchone()["stock"]
            cart_count = connection.execute(
                "SELECT COUNT(*) FROM cart_items WHERE user_id = ?",
                (customer["id"],),
            ).fetchone()[0]

        self.assertEqual(order["user_id"], customer["id"])
        self.assertEqual(order["total_cents"], 5000)
        self.assertEqual(order["status"], "New")
        self.assertEqual(order["payment_method"], "bank_transfer")
        self.assertEqual(order["points_awarded"], 50)
        self.assertEqual(app.get_user_by_id(customer["id"])["points_balance"], 50)
        self.assertEqual(stock, 98)
        self.assertEqual(cart_count, 0)

    def test_catalog_adds_ten_products_without_resetting_existing_stock(self) -> None:
        with app.database() as connection:
            connection.execute("UPDATE products SET stock = 7 WHERE id = 'mug'")

        app.initialize_store()
        products = app.get_products()
        product_by_id = {product["id"]: product for product in products}

        self.assertEqual(len(products), 14)
        self.assertEqual(product_by_id["mug"]["stock"], 7)
        self.assertIn("gift-set", product_by_id)

    def test_order_rejects_unknown_payment_method(self) -> None:
        customer = self.create_user("customer@example.com")
        app.add_to_cart(customer["id"], "mug", 1)

        order_id, error = app.place_order(customer["id"], "card")

        self.assertIsNone(order_id)
        self.assertIsNotNone(error)
        self.assertEqual(app.get_cart_items(customer["id"])[0]["quantity"], 1)

    def test_storefront_shows_cart_count_categories_and_personal_recommendations(self) -> None:
        customer = self.create_user("customer@example.com")
        self.assertIsNone(app.add_to_cart(customer["id"], "mug", 2))

        storefront = app.storefront_page(customer, "csrf-token").decode("utf-8")

        self.assertIn('class="cart-count">2</span>', storefront)
        self.assertIn('id="category-0"', storefront)
        self.assertIn('id="category-1"', storefront)
        self.assertIn('id="category-2"', storefront)
        self.assertEqual(storefront.count("EXPLORE A CATEGORY"), 3)
        self.assertIn("Picked from categories in your cart and past orders.", storefront)
        self.assertIn("Coastline candle set", storefront)

    def test_cart_page_shows_item_count_and_checkout_total(self) -> None:
        customer = self.create_user("customer@example.com")
        app.add_to_cart(customer["id"], "mug", 2)

        cart = app.cart_page(customer, "csrf-token").decode("utf-8")

        self.assertIn("Total for 2 item(s)", cart)
        self.assertIn("Total due at checkout", cart)
        self.assertIn("$50.00", cart)
        self.assertIn("Cash on delivery", cart)

    def test_cart_rejects_unavailable_quantities(self) -> None:
        customer = self.create_user("customer@example.com")

        self.assertIsNotNone(app.add_to_cart(customer["id"], "missing", 1))
        self.assertIsNotNone(app.add_to_cart(customer["id"], "mug", 101))
        self.assertEqual(app.get_cart_items(customer["id"]), [])

    def test_startup_clears_existing_sessions(self) -> None:
        customer = self.create_user("customer@example.com")
        app.create_session("session-hash", "csrf-token", customer["id"], 2_000_000_000)

        app.initialize_store()

        with app.database() as connection:
            session_count = connection.execute(
                "SELECT COUNT(*) FROM sessions"
            ).fetchone()[0]
        self.assertEqual(session_count, 0)

    def test_existing_admin_account_is_promoted_and_signups_are_customers(self) -> None:
        app.DATABASE_PATH.unlink()
        connection = sqlite3.connect(app.DATABASE_PATH)
        try:
            connection.execute(
                "CREATE TABLE users ("
                "id TEXT PRIMARY KEY, name TEXT NOT NULL, surname TEXT NOT NULL, "
                "email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, "
                "created_at INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "existing-admin",
                    "Store",
                    "Owner",
                    app.ADMIN_BOOTSTRAP_EMAIL,
                    app.hash_password("owner-password"),
                    1,
                ),
            )
            connection.commit()
        finally:
            connection.close()

        app.initialize_store()
        admin = app.get_user_by_email(app.ADMIN_BOOTSTRAP_EMAIL)
        customer = self.create_user("new-customer@example.com", "customer-2")

        self.assertIsNotNone(admin)
        self.assertEqual(admin["role"], "admin")
        self.assertEqual(customer["role"], "customer")


if __name__ == "__main__":
    unittest.main()
