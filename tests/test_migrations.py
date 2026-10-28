import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class MigrationTests(unittest.TestCase):
    def test_initial_revision_upgrades_legacy_store_without_losing_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "legacy.sqlite3"
            connection = sqlite3.connect(database_path)
            connection.executescript(
                """
                CREATE TABLE users (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, surname TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE sessions (
                    token_hash TEXT PRIMARY KEY, csrf_token TEXT NOT NULL,
                    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                    expires_at INTEGER NOT NULL
                );
                CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);
                CREATE TABLE app_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE products (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
                    description TEXT NOT NULL, price_cents INTEGER NOT NULL, stock INTEGER NOT NULL
                );
                CREATE TABLE cart_items (
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    product_id TEXT NOT NULL REFERENCES products(id),
                    quantity INTEGER NOT NULL, PRIMARY KEY (user_id, product_id)
                );
                CREATE TABLE orders (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                    total_cents INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'New',
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE order_items (
                    order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
                    product_id TEXT NOT NULL REFERENCES products(id),
                    product_name TEXT NOT NULL, quantity INTEGER NOT NULL,
                    unit_price_cents INTEGER NOT NULL, PRIMARY KEY (order_id, product_id)
                );
                INSERT INTO users VALUES ('legacy-user', 'Legacy', 'Customer',
                    'legacy@example.com', 'old-hash', 1700000000);
                INSERT INTO products VALUES ('legacy-product', 'Old product', 'Old',
                    'Existing catalog entry', 1000, 7);
                """
            )
            connection.commit()
            connection.close()

            environment = os.environ.copy()
            environment["DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
            result = subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=PROJECT_ROOT, env=environment, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            connection = sqlite3.connect(database_path)
            user = connection.execute(
                "SELECT role, points_balance FROM users WHERE id = 'legacy-user'"
            ).fetchone()
            old_product = connection.execute(
                "SELECT stock FROM products WHERE id = 'legacy-product'"
            ).fetchone()
            apparel_count = connection.execute(
                "SELECT COUNT(*) FROM products WHERE category IN ('Women', 'Men', 'Accessories')"
            ).fetchone()[0]
            order_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(orders)")
            }
            connection.close()

            self.assertEqual(user, ("customer", 0))
            self.assertEqual(old_product, (7,))
            self.assertEqual(apparel_count, 10)
            self.assertIn("payment_method", order_columns)
            self.assertIn("points_awarded", order_columns)


if __name__ == "__main__":
    unittest.main()