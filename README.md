# RoleCart - Role-Based E-Commerce Demo

A small full-stack e-commerce app with two separate roles. Customers browse and order products. Admins manage products and validate (approve or reject) every order before it is fulfilled.

**Live app:** `<add your Render URL here>`
**Demo video:** `<add your video link here>`

## Demo logins (dummy accounts)

| Role | Email | Password |
|---|---|---|
| Customer | customer@demo.com | Customer@123 |
| Admin | admin@demo.com | Admin@123 |

The hosted app can take 30-60 seconds to wake up on the first visit (free hosting).

## Features

**Customer**
- Sign up and log in (sign-up always creates a customer account)
- Browse products with price and live stock
- Cart with quantity controls
- Place an order (starts as **Pending**)
- "My orders" page showing Pending, Approved or Rejected, plus any admin note

**Admin**
- Order validation: list orders by status, approve or reject with an optional note
- Product management: add, edit, delete products and set stock
- Approving an order reduces stock automatically. If stock is not enough, the approval is blocked and the order stays Pending.

## How role-based access control works

1. On login the server creates a signed **JWT** that contains the user id and role. The token expires after 8 hours.
2. Every protected API route first runs an `auth` middleware that verifies the token.
3. A `requireRole(...)` middleware then checks the role:
   - Product create, update, delete: **admin only**
   - View all orders, approve, reject: **admin only**
   - Place an order and view "my orders": **customer only**
4. A wrong role gets **403 Access denied**, and a missing or invalid token gets **401**.
5. The UI also shows a different screen per role (customer shop vs admin dashboard), but security does not depend on the UI. The server enforces every rule.
6. Public sign-up cannot create admins. The admin account is created by the server at startup from configuration.

Other safeguards: passwords are hashed with bcrypt, order prices are always read from the database (not from the browser), orders can only be reviewed once, and all user content is escaped in the page.

## Order flow

`Customer places order -> PENDING -> Admin approves (stock reduced) -> APPROVED`
`                                  -> Admin rejects               -> REJECTED`

## Tech stack

- Backend: Node.js, Express
- Database: MongoDB (Mongoose)
- Auth: JWT (jsonwebtoken), bcryptjs
- Frontend: plain HTML, CSS and JavaScript served by the same Express app (one deployable service)

## Database structure (MongoDB)

- **users**: name, email (unique), passwordHash, role (`customer` or `admin`)
- **products**: name, description, category, price, stock, imageUrl
- **orders**: user (ref), items [product, name, price, quantity], total, status (`PENDING`, `APPROVED`, `REJECTED`), adminNote, reviewedAt

## API summary

| Method | Route | Access |
|---|---|---|
| POST | /api/auth/register | public |
| POST | /api/auth/login | public |
| GET | /api/auth/me | logged in |
| GET | /api/products | public |
| POST, PUT, DELETE | /api/products, /api/products/:id | admin |
| POST | /api/orders | customer |
| GET | /api/orders/mine | customer |
| GET | /api/orders | admin |
| PATCH | /api/orders/:id/approve, /reject | admin |

## Run locally

```
npm install
MONGODB_URI="your-mongodb-connection-string" JWT_SECRET="any-long-random-text" npm start
```
Open http://localhost:3000. Demo users and sample products are created automatically on first start.

## Environment variables

| Name | Purpose |
|---|---|
| MONGODB_URI | MongoDB connection string (required) |
| JWT_SECRET | Secret used to sign tokens (required in production) |
| ADMIN_EMAIL, ADMIN_PASSWORD | Optional: change the seeded admin login |
| PORT | Set automatically by most hosts |

## Deploy (free)

1. Create a free MongoDB Atlas cluster and copy the connection string.
2. On Render, choose **New > Blueprint** and select this repo. `render.yaml` sets everything up. Paste your `MONGODB_URI` when asked (`JWT_SECRET` is generated automatically).
   Manual alternative: **New > Web Service**, build command `npm install`, start command `npm start`, and add `MONGODB_URI` and `JWT_SECRET` as environment variables.

## Challenges and improvements

- Preventing double-processing of an order: solved by claiming the order with an atomic "only if still Pending" update, and rolling back if stock is short.
- Keeping security on the server: every rule is checked in middleware, not only hidden in the UI.
- With more time: automated tests, order history for each product, pagination, password reset, image upload, and a CI pipeline with GitHub Actions and Docker.
