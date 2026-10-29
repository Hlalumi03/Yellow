# Yellow Clothing

Yellow is a server-rendered clothing storefront with a versioned JSON API. The
backend is organized as a small Clean Architecture application: domain rules do
not depend on FastAPI or SQLAlchemy, application services depend on repository
ports, and infrastructure provides SQLAlchemy implementations.

## Architecture

```text
backend/
  domain/          Entities, enums, and business exceptions
  application/     Use cases and repository protocols
  infrastructure/  SQLAlchemy models, sessions, and repository adapters
  presentation/    FastAPI app factory, API schemas, routes, and web pages
migrations/        Alembic environment and versioned schema revisions
frontend/          Jinja2 templates and storefront styles
tests/             Isolated API and workflow tests
```

## Run locally

Use Python 3.11 or newer. From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
alembic upgrade head
python main.py
```

Open `http://127.0.0.1:8000`. Interactive API documentation is available at
`/api/docs`; the liveness endpoint is `/healthz`. For a production server, use
`uvicorn backend.app:app --host 0.0.0.0 --port 8000` behind a TLS-terminating
reverse proxy and a process manager.

## Configuration

Settings are read from environment variables or `.env`:

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | SQLAlchemy database URL | `yellow_store.sqlite3` |
| `ENVIRONMENT` | Deployment environment label | `development` |
| `SECURE_COOKIES` | Mark the session cookie Secure | `false` |
| `ALLOWED_ORIGINS` | Optional JSON list of trusted browser origins | `[]` |

Use PostgreSQL for a multi-worker deployment. Set `SECURE_COOKIES=true` when
serving through HTTPS. Apply schema changes with `alembic upgrade head` during
deployment; the application does not mutate schema at startup.

## Accounts and admin access

Public sign-up always creates customer accounts. Promote a separately created
owner account with `python -m backend.cli make-admin owner@example.com`, then
sign in at `/admin/signin`. Do not use customer sign-up as an administrator
bootstrap mechanism.

## API

All JSON resources are under `/api/v1`:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/products` | Browse products; accepts `category`, `limit`, and `offset` |
| `GET` | `/products/{product_id}` | Get a product |
| `GET` | `/auth/csrf` | Start an anonymous session and retrieve a CSRF token |
| `POST` | `/auth/signup` | Create an account and start an authenticated session |
| `POST` | `/auth/session` | Sign in |
| `DELETE` | `/auth/session` | Sign out |
| `GET` | `/cart` | Get the signed-in customer’s cart |
| `POST` | `/cart/items` | Add a product and quantity |
| `DELETE` | `/cart/items/{product_id}` | Remove a cart line |
| `GET` | `/orders` | List the signed-in customer’s orders; accepts `limit` and `offset` |
| `POST` | `/orders` | Place an order from the current cart |
| `GET` | `/orders/{order_id}` | Get an order owned by the signed-in customer |

Authentication uses an HttpOnly session cookie. Send the returned CSRF token in
`X-CSRF-Token` for state-changing API requests. Successful order creation
returns `201 Created`; validation and business errors use structured HTTP
responses.

## Scope before a public launch

The included payment choices record an order only; there is no payment
processor, shipping integration, tax calculation, returns workflow, or
inventory-adjustment audit trail. Product variants (size/color), customer
addresses, email verification, password recovery, rate limiting, observability,
and deployment-specific secrets still need to be designed for the store’s
actual requirements. The sample catalog is seeded by the first Alembic
revision. Review security, privacy, and operational requirements before
accepting real customer data or payments.

## Tests

```powershell
python -m unittest discover -s tests -v
```