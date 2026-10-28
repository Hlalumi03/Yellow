import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.infrastructure.database import Base
from backend.infrastructure.models import ProductModel, UserModel
from backend.presentation.app import app
from backend.infrastructure.database import get_session


class StoreApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "test.sqlite3"
        self.engine = create_engine(
            f"sqlite:///{database_path.as_posix()}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

        def override_session():
            session = self.session_factory()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_session] = override_session
        self.client = TestClient(app)
        with self.session_factory() as session:
            session.add_all([
                ProductModel(
                    id="linen-shirt", name="Relaxed linen shirt", category="Women",
                    description="Breathable linen.", price_cents=6800, stock=24,
                ),
                ProductModel(
                    id="sold-out", name="Sold out item", category="Accessories",
                    description="Unavailable.", price_cents=1500, stock=0,
                ),
            ])
            session.commit()
        self.addCleanup(self.temp_dir.cleanup)
        self.addCleanup(self.engine.dispose)
        self.addCleanup(app.dependency_overrides.clear)
        self.addCleanup(self.client.close)

    def signup(self) -> str:
        token = self.client.get("/api/v1/auth/csrf").json()["csrf_token"]
        response = self.client.post(
            "/api/v1/auth/signup",
            headers={"X-CSRF-Token": token},
            json={
                "name": "Test", "surname": "Customer",
                "email": "customer@example.com", "password": "correct horse battery staple",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["csrf_token"]

    def test_product_catalog_and_storefront_render(self) -> None:
        products = self.client.get("/api/v1/products")
        self.assertEqual(products.status_code, 200)
        self.assertIn("linen-shirt", {product["id"] for product in products.json()})

        csrf = self.signup()
        page = self.client.get("/shop")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Relaxed linen shirt", page.text)
        self.assertIn(csrf, page.text)

    def test_customer_can_add_to_cart_and_checkout(self) -> None:
        csrf = self.signup()
        added = self.client.post(
            "/api/v1/cart/items", headers={"X-CSRF-Token": csrf},
            json={"product_id": "linen-shirt", "quantity": 2},
        )
        self.assertEqual(added.status_code, 201, added.text)
        self.assertEqual(added.json()["line_total_cents"], 13600)

        cart = self.client.get("/api/v1/cart")
        self.assertEqual(cart.json()["total_cents"], 13600)
        order = self.client.post(
            "/api/v1/orders", headers={"X-CSRF-Token": csrf},
            json={"payment_method": "bank_transfer"},
        )
        self.assertEqual(order.status_code, 201, order.text)
        self.assertEqual(order.json()["total_cents"], 13600)
        self.assertEqual(order.json()["points_awarded"], 136)
        self.assertEqual(order.json()["items"][0]["quantity"], 2)

        with self.session_factory() as session:
            product = session.get(ProductModel, "linen-shirt")
            customer = session.scalar(select(UserModel).where(UserModel.email == "customer@example.com"))
            self.assertEqual(product.stock, 22)
            self.assertEqual(customer.points_balance, 136)

    def test_rejects_overselling_and_missing_csrf(self) -> None:
        csrf = self.signup()
        invalid = self.client.post(
            "/api/v1/cart/items", headers={"X-CSRF-Token": csrf},
            json={"product_id": "linen-shirt", "quantity": 25},
        )
        self.assertEqual(invalid.status_code, 400)

        no_csrf = self.client.post(
            "/api/v1/cart/items", json={"product_id": "linen-shirt", "quantity": 1},
        )
        self.assertEqual(no_csrf.status_code, 403)

    def test_api_docs_health_and_authentication(self) -> None:
        self.assertEqual(self.client.get("/healthz").json(), {"status": "ok"})
        self.assertEqual(self.client.get("/api/openapi.json").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/cart").status_code, 401)


if __name__ == "__main__":
    unittest.main()