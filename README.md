# Yellow Store

Yellow is a local storefront prototype with customer accounts, a sample catalog,
cart and order recording, and a role-protected admin dashboard.

## Run locally

Run `python main.py` from the project directory and open
`http://127.0.0.1:8000`. The app opens on sign-in, and restarting the server
invalidates existing sessions so every start requires a fresh sign-in. New
customers can create an account from the sign-in page.

## Accounts and admin access

The existing store-owner account selected for this project is promoted to the
admin role once when the application initializes its database. Existing and
new non-admin accounts use the customer storefront. Public sign-up always
creates customer accounts; it cannot grant admin access.

The admin dashboard at `/account` shows customer registrations, recorded
orders, product counts, and the total value of orders. Order totals are not
proof of payment.

## Store and checkout

The starter catalog contains 14 products, including a ceramics mug, linen tote,
candle set, stationery, and home goods. Customers can add in-stock products to
a cart and place an order.
Checkout records the customer, items, quantities, order value, and time, and
reserves the ordered stock. At checkout, customers can select cash on delivery,
bank transfer, or pay on pickup; the selected method is saved with the order,
but this prototype does not process payments or arrange delivery. Customers
earn 1 reward point per whole dollar in an order, credited when the order is
placed. The customer storefront displays the current points balance.

The development server binds to localhost and is not configured for public
internet deployment. A production launch needs a production web server, HTTPS,
deployment-specific admin provisioning, and a payment provider if online
payments are required.
