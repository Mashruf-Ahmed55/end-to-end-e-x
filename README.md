# Multi‑Vendor E‑Commerce (Microservices) — Complete Roadmap & Database Design

**Author:** Boss’s build plan
**Style:** Practical, future‑proof, no code — just the full blueprint
**Goal:** Amazon/eBay/Walmart‑style store with **multi‑vendor**, **scalable** microservices, and **AI** extensions.

---

## Table of Contents

1. [Scope & Principles](#scope--principles)
2. [High‑Level Architecture](#high-level-architecture)
3. [Roadmap (Step‑by‑Step)](#roadmap-step-by-step)
4. [Service Contracts (High‑Level APIs)](#service-contracts-high-level-apis)
5. [Event Model (Message Broker Topics)](#event-model-message-broker-topics)
6. [Database Design (Per Service)](#database-design-per-service)
7. [AI Service (Feature Store + Models)](#ai-service-feature-store--models)
8. [Search Service (Optional, Elastic/Typesense)](#search-service-optional-elastictypeSense)
9. [Admin/Back‑office Service](#adminback-office-service)
10. [Security, Compliance & SRE](#security-compliance--sre)
11. [Testing Strategy](#testing-strategy)
12. [Deployment & Environments](#deployment--environments)
13. [Config Matrix (.env)](#config-matrix-env)
14. [Future Enhancements Backlog](#future-enhancements-backlog)
15. [Glossary](#glossary)

---

## Scope & Principles

**Build type:** Multi‑vendor marketplace with customer storefront, vendor portal, and super‑admin back office.
**Key goals:**

- Independent **microservices** per domain
- **Event‑driven** integrations (Kafka/RabbitMQ)
- **Database per service** (no tight coupling)
- **Zero‑downtime** deploys, versioned APIs
- **AI‑ready** from day one (recommendations, fraud, forecasting)

**Non‑goals (MVP):** No international tax engine, no warehouse robotics, no marketplace loans.

---

## High‑Level Architecture

**Edge & Infra**

- API Gateway (Kong/Traefik) + Auth (JWT/opaque tokens)
- Message Broker (Kafka/RabbitMQ/NATS)
- Cache & Jobs (Redis)
- Object Storage (S3/Cloudinary for images)
- Observability: Prometheus + Grafana, ELK/OpenSearch, Jaeger
- CI/CD: GitHub Actions / GitLab CI
- Orchestration: Docker → Kubernetes (K8s)

**Core Services**

- **Auth Service**
- **User Profile Service**
- **Vendor Service** (onboarding, KYC, commissions)
- **Catalog Service** (products, categories, variants/SKUs)
- **Inventory Service** (stock & reservations)
- **Cart Service**
- **Coupon/Promotion Service**
- **Order Service**
- **Payment Service** (Stripe/SSLCommerz; webhooks)
- **Shipping Service** (rates, labels, tracking)
- **Review & Rating Service**
- **Notification Service** (email/SMS/push)
- **Search Service** (Elastic/Typesense) — optional
- **AI Service** (recs, fraud, pricing, forecasting)
- **Admin/Back‑office Service** (super admin + vendor admin UI)

---

## Roadmap (Step‑by‑Step)

### Phase 0 — Foundations (1–2 weeks)

- Decide cloud (VPS → K8s later), pick broker (Kafka/RabbitMQ).
- Set up mono‑repo or poly‑repo; enable CI/CD.
- Create **API Gateway** routes skeleton; JWT validation at edge.
- Global **logging/trace** headers (requestId, userId).

**Deliverables:** Gateway online; hello‑world for 2 services; shared tracing/logging libs.

---

### Phase 1 — Identity & Vendor Onboarding (1–2 weeks)

- **Auth Service:** register/login, access+refresh tokens, roles (`super_admin`, `vendor_admin`, `staff`, `customer`).
- **User Profile Service:** addresses & preferences.
- **Vendor Service:** vendor application, KYC docs, bank details, commission rules, status (pending/active/suspended).

**Deliverables:** Vendor can apply; admin can approve; JWT carries `vendorId` when applicable.

---

### Phase 2 — Catalog & Media (2–3 weeks)

- **Catalog Service:** categories, brands, product → variants/SKUs, attributes, SEO, approval flow.
- **Media Storage:** S3/Cloudinary upload pipeline.
- **Search indexing hooks** (emit `product.index.requested`).

**Deliverables:** Vendor can submit product; admin approve → product live.

---

### Phase 3 — Inventory & Pricing (1–2 weeks)

- **Inventory Service:** per‑SKU stock, reservations, safety stock.
- **Pricing:** base price, compare‑at, tax class; future rule hooks.
- Low‑stock alerts (Notification service).

**Deliverables:** Accurate stock visible; reservation on checkout draft.

---

### Phase 4 — Cart & Coupons (1–2 weeks)

- **Cart Service:** per‑user cart (SKU, qty, priceAtAdd); server‑side totals.
- **Coupon/Promotion Service:** codes, scopes (vendor/category/product), validity windows, usage limits.

**Deliverables:** Reliable cart; coupons apply server‑side; totals returned via `/summary`.

---

### Phase 5 — Checkout, Orders & Payments (2–3 weeks)

- **Order Service:** order creation, validation, vendor split (per item/vendor).
- **Payment Service:** create intent/session, handle webhooks; update order on success/fail.
- **Inventory:** reservation → commit on payment success (time‑boxed TTL release).

**Deliverables:** Full purchase loop from cart → paid order; emails sent.

---

### Phase 6 — Shipping & Fulfillment (1–2 weeks)

- **Shipping Service:** flat/table rates MVP; tracking number; label integration later.
- **Order Service:** fulfillment timeline (processing → shipped → delivered).

**Deliverables:** Customers can track orders; vendors can mark shipped.

---

### Phase 7 — Reviews, Notifications, Disputes (1–2 weeks)

- **Review Service:** verified purchases only; moderation.
- **Notification Service:** templates, email/SMS providers; async queue.
- **Refund/Return (basic):** RMA stub, manual refunds through Payment service.

**Deliverables:** Review flow; order emails; manual refund path.

---

### Phase 8 — Admin/Back‑office Dashboards (2–3 weeks)

- **Super Admin UI:** vendors, approvals, global products, orders, payouts, site settings.
- **Vendor Admin UI:** own catalog, orders, earnings, stock alerts.
- Analytics v1 (see metrics below).

**Deliverables:** Role‑aware dashboards hitting microservice APIs.

---

### Phase 9 — AI & Search Enhancements (2–4 weeks, parallelizable)

- **AI Service:** Recommendations v1 (co‑purchase + trending), basic fraud rules, inventory forecasting MVP.
- **Search Service:** Elastic/Typesense indexing + typo/semantic search.

**Deliverables:** “Recommended For You” widgets; better search; fraud flags on risky orders.

---

### Phase 10 — Analytics & Data Warehouse (2–3 weeks)

- Event ingestion → warehouse (BigQuery/Redshift/ClickHouse).
- Materialized views for GMV, AOV, cohort, repeat rate, vendor earnings.
- BI dashboards (Metabase/Superset).

**Deliverables:** Decision‑grade dashboards; scheduled reports & alerts.

---

## Service Contracts (High‑Level APIs)

> **Note:** Routes are **illustrative**; keep versioned (`/v1/...`) and guarded by JWT and RBAC.

**Auth**

- `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`
- `POST /auth/forgot-password`, `POST /auth/reset-password`

**User Profile**

- `GET /me`, `PATCH /me`
- `GET /me/addresses`, `POST /me/addresses`, `PATCH /me/addresses/:id`, `DELETE /me/addresses/:id`

**Vendor**

- `POST /vendors/apply`, `GET /vendors/:id`, `PATCH /vendors/:id`
- `POST /vendors/:id/kyc`, `POST /vendors/:id/bank`
- Admin: `GET /admin/vendors`, `PATCH /admin/vendors/:id/status`

**Catalog**

- `GET /categories`, `POST /admin/categories`, `PATCH /admin/categories/:id`
- `GET /products`, `GET /products/:slug`
- Vendor: `POST /vendors/:vendorId/products`, `PATCH /vendors/:vendorId/products/:id`
- Admin: `PATCH /admin/products/:id/approve`

**Inventory**

- `GET /inventory/:sku`
- Vendor: `PATCH /vendors/:vendorId/inventory/:sku`

**Cart**

- `GET /cart`, `POST /cart/items`, `PATCH /cart/items/:sku`, `DELETE /cart/items/:sku`
- `POST /cart/apply-coupon`, `DELETE /cart/coupon`
- `POST /checkout/summary`

**Order**

- `POST /orders` (create), `GET /orders/:orderNo`, `GET /me/orders`
- Admin/Vendor: `GET /admin/orders`, `PATCH /admin/orders/:id/status`

**Payment**

- `POST /payments/intent`, `POST /payments/webhook`
- Payouts: `GET /vendors/:id/earnings`, `POST /vendors/:id/payout-request`, Admin approve

**Shipping**

- `POST /shipping/rates`, `POST /shipping/labels`, `GET /shipping/track/:trackingNo`

**Review**

- `POST /reviews`, `GET /products/:id/reviews`, Admin moderation

**Notification**

- `POST /notify/email`, templates CRUD (admin)

**AI**

- `GET /ai/recommendations?userId=...&context=...`
- `POST /ai/fraud/evaluate`

**Search**

- `GET /search?q=...`

---

## Event Model (Message Broker Topics)

**Topics (examples):**

- `user.created`, `vendor.applied`, `vendor.approved`
- `product.created`, `product.approved`, `product.price.updated`
- `inventory.low_stock`, `inventory.reserved`, `inventory.released`, `inventory.committed`
- `cart.checked_out`
- `order.created`, `order.paid`, `order.fulfilled`, `order.cancelled`, `order.return_requested`
- `payment.intent.created`, `payment.succeeded`, `payment.failed`, `payout.requested`, `payout.processed`
- `shipping.label.created`, `shipping.status.updated`
- `review.submitted`, `review.approved`
- `ai.recommendation.requested`, `ai.recommendation.served`

**Event envelope:**

```json
{
  "eventId": "uuid",
  "type": "order.paid",
  "occurredAt": "ISO8601",
  "actor": { "type": "user|system", "id": "..." },
  "data": {
    /* domain payload */
  },
  "trace": { "requestId": "...", "correlationId": "..." }
}
```

(Use schemas and version each event.)

---

## Database Design (Per Service)

> **Rule:** **One DB per service.** Use the best fit. Include **indexes** and **status** fields for workflows.

### Auth Service (PostgreSQL)

- **users**
  - `id (pk, uuid)`, `email (unique, idx)`, `password_hash`, `status (active|blocked|pending)`,
    `created_at`, `updated_at`, `last_login_at`
- **roles**: `id`, `name (unique)` → seed: `super_admin`, `vendor_admin`, `staff`, `customer`
- **user_roles**: `user_id (idx)`, `role_id (idx)`
- **refresh_tokens**: `id`, `user_id`, `token_hash (unique)`, `expires_at`, `revoked_at`
- **permissions** (optional granular): `id`, `key (unique)`
- **role_permissions**: `role_id`, `perm_id`

**Indexes:** users.email, user_roles.user_id, refresh_tokens.token_hash

---

### User Profile Service (PostgreSQL)

- **profiles**: `user_id (pk, fk)`, `name`, `phone`, `avatar_url`, `dob`, `marketing_opt_in`, timestamps
- **addresses**: `id`, `user_id (idx)`, `label`, `line1`, `line2`, `city`, `state`, `postal_code`, `country`, `is_default`, timestamps

**Indexes:** addresses.user_id, (user_id, is_default)

---

### Vendor Service (PostgreSQL)

- **vendors**
  - `id (pk, uuid)`, `owner_user_id (idx)`, `name`, `slug (unique)`, `logo_url`,
    `status (pending|active|suspended|rejected)`, `commission_type (percent|fixed)`, `commission_value`,
    `support_email`, `support_phone`, `created_at`, `updated_at`
- **vendor_kyc_docs**: `id`, `vendor_id (idx)`, `doc_type`, `doc_url`, `verified_at`, `status`
- **vendor_bank_accounts**: `id`, `vendor_id (idx)`, `account_holder`, `account_no|iban`, `bank_name`, `routing`, `country`, `is_default`, `verified_at`
- **vendor_earnings** (roll‑up by order or period): `id`, `vendor_id (idx)`, `order_id`, `gross`, `commission`, `fees`, `net`, `currency`, `status (pending|eligible|paid)`, timestamps
- **vendor_payouts**: `id`, `vendor_id (idx)`, `amount`, `currency`, `method`, `external_ref`, `status (requested|processing|paid|failed)`, timestamps

**Indexes:** vendors.slug, vendor_earnings.vendor_id, vendor_payouts.vendor_id

---

### Catalog Service (MongoDB)

- **categories**
  - `_id`, `name`, `slug (unique)`, `parentId?`, `path` (e.g., "electronics>phones"), `isActive`, `sortOrder`, timestamps
- **brands**: `_id`, `name (unique)`, `slug`, `logo_url`, `isActive`
- **products**
  - `_id`, `vendorId`, `title`, `slug (unique)`, `description`, `categoryIds[]`, `brandId?`, `images[]`,
    `attributes { key: value }`, `options [{ name, values[] }]`,
    `status (draft|pending|active|archived)`, `seo { title, description, keywords[] }`,
    `ratingAvg`, `ratingCount`, timestamps
- **variants** (separate collection helps indexing SKUs)
  - `_id`, `productId (idx)`, `vendorId (idx)`, `sku (unique, idx)`, `optionValues { Size: "M", Color: "Black" }`,
    `price`, `compareAtPrice?`, `taxClass`, `weight`, `dimensions { l,w,h }`, `barcode?`, `image?`, `isActive`, timestamps

**Indexes:** products.slug, products.vendorId, variants.sku, variants.productId, categories.slug

---

### Inventory Service (PostgreSQL or MongoDB)

- **inventory**
  - `id/_id`, `sku (unique, idx)`, `product_id`, `vendor_id`,
    `quantity_on_hand`, `quantity_reserved`, `reorder_point`, `warehouse_id?`, timestamps
- **reservations**: `id/_id`, `order_id`, `sku`, `qty`, `expires_at (idx)`

**Indexes:** inventory.sku, reservations.expires_at

---

### Cart Service (Redis + Persistent Store e.g., MongoDB)

- **carts** (MongoDB)
  - `_id`, `userId (idx)`, `items: [{ sku, productId, vendorId, title, image, priceAtAdd, qty, optionValues }]`,
    `couponCode?`, `currency`, `updatedAt`
- **cart_events** (audit/debug): `_id`, `cartId`, `type`, `data`, `at`

**Indexes:** carts.userId

---

### Coupon/Promotion Service (PostgreSQL)

- **coupons**: `id`, `code (unique, idx)`, `type (percent|fixed)`, `value`, `min_order_amount?`, `max_discount?`, `starts_at`, `ends_at`, `is_active`, timestamps
- **coupon_scopes**: `id`, `coupon_id (idx)`, `scope_type (vendor|category|product|user)`, `ref_id`
- **coupon_usages**: `id`, `coupon_id (idx)`, `user_id (idx)`, `order_id`, `used_at`

**Indexes:** coupons.code, coupon_usages.user_id

---

### Order Service (PostgreSQL)

- **orders**
  - `id (pk, uuid)`, `order_no (unique, idx)`, `user_id (idx)`, `status (unfulfilled|processing|shipped|delivered|cancelled|returned)`,
    `payment_status (pending|paid|failed|refunded|partial)`,
    `amounts { subtotal, discount, shipping, tax, total, currency }`,
    `shipping_method`, `placed_at`, `delivered_at?`, timestamps
- **order_items**: `id`, `order_id (idx)`, `vendor_id (idx)`, `product_id`, `sku`, `title`, `price`, `qty`, `subtotal`
- **order_addresses**: `order_id (pk, fk)`, `shipping_json`, `billing_json`
- **order_timeline**: `id`, `order_id (idx)`, `event`, `note?`, `at`, `by_user_id?`

**Indexes:** orders.order_no, order_items.vendor_id, orders.user_id

---

### Payment Service (PostgreSQL)

- **payments**: `id`, `order_id (idx)`, `provider (stripe|sslcommerz)`, `intent_id`, `status`, `amount`, `currency`, `raw_json`, `created_at`
- **refunds**: `id`, `payment_id (idx)`, `amount`, `reason`, `status`, `raw_json`, `created_at`
- **payouts** (to vendors; or kept in Vendor service): `id`, `vendor_id`, `amount`, `status`, `method`, `external_ref`, `created_at`

**Indexes:** payments.intent_id, payments.order_id

---

### Shipping Service (PostgreSQL)

- **shipments**: `id`, `order_id (idx)`, `carrier`, `service_level`, `tracking_no (idx)`, `label_url?`, `status (label_created|in_transit|delivered|exception)`, `shipped_at`, `delivered_at`
- **rates_cache**: `id`, `hash`, `request_json`, `response_json`, `expires_at`

**Indexes:** shipments.order_id, shipments.tracking_no

---

### Review & Rating Service (MongoDB)

- **reviews**: `_id`, `userId (idx)`, `productId (idx)`, `orderId?`, `rating (1..5)`, `title?`, `body?`, `images[]`, `isApproved`, timestamps
- **review_flags**: `_id`, `reviewId (idx)`, `reason`, `createdBy`

**Indexes:** reviews.productId, reviews.userId

---

### Notification Service (PostgreSQL)

- **templates**: `id`, `key (unique)`, `subject`, `body_md`, `channel (email|sms|push)`
- **messages**: `id`, `template_key`, `to`, `payload_json`, `status (queued|sent|failed)`, `provider`, `error?`, `created_at`, `sent_at?`

**Indexes:** messages.status, messages.created_at

---

### Search Service (Elastic/Typesense)

- **indices:** `products`, `variants`, `vendors`
- Indexed fields: `title`, `description`, `category`, `brand`, `attributes`, `price`, `ratingAvg`, `vendor`, `status`
- Synonyms, typo tolerance, popularity score (views/sales).

---

## AI Service (Feature Store & Models)

**Data Sources:** Orders, Catalog, Inventory, Search logs, Reviews, Clickstream.
**Storage:**

- **Feature Store** (e.g., Redis/Feast/DB tables)
- **Models Registry** (which model/version is live)
- **Recommendations Cache** per user/session

**Core Use‑cases:**

1. **Recommendations** (“similar items”, “frequently bought together”, “for you”)
   - Inputs: userId, context (product/category/home), recency
   - Outputs: list of productIds (ranked)
   - Tables:
     - `ai_reco_requests`: `id`, `user_id`, `context`, `at`
     - `ai_reco_results`: `id`, `request_id`, `product_ids[]`, `model_version`, `latency_ms`
2. **Fraud Scoring**
   - Inputs: order features (risk signals), payment history, device fingerprint
   - Outputs: score (0–1) + reasons
   - Tables:
     - `ai_fraud_scores`: `order_id`, `score`, `reasons_json`, `model_version`, `at`
3. **Inventory Forecasting**
   - Inputs: historical sales, seasonality, promo flags
   - Outputs: days to stock‑out, recommended reorder qty
   - Tables:
     - `ai_forecasts`: `sku`, `horizon_days`, `forecast_qty`, `model_version`, `at`
4. **Dynamic Pricing (later)**
   - Inputs: demand, stock, competitor signals
   - Outputs: suggested price changes
   - Tables:
     - `ai_price_suggestions`: `sku`, `suggested_price`, `confidence`, `at`

**Interfaces:**

- `GET /ai/recommendations`
- `POST /ai/fraud/evaluate`
- Event listeners: `order.created`, `order.paid`, `product.viewed`

---

## Search Service (Optional, Elastic/Typesense)

**Pipelines:**

- Listen to `product.created|updated|approved` → index/update
- Denormalize fields: category path, vendor name, price, rating
- Rank by text relevance + sales/popularity + freshness

**Tuning:**

- Synonyms (`tv` ↔ `television`), typos, Bengali/English tokenization
- Filters: price range, brand, vendor, rating, attributes

---

## Admin/Back‑office Service

**Roles:**

- **Super Admin:** all vendors/products/orders/payments/settings
- **Vendor Admin:** own catalog, orders, earnings, payouts
- **Staff:** limited support/refund permissions

**Analytics v1 (must‑have):**

- **GMV, AOV, Orders/day, Conversion rate**
- **Vendor earnings & payout status**
- **Top categories/products, low stock**
- **Refund rate, on‑time delivery**

**Data Sources:**

- Orders + Payments (primary), Inventory (low‑stock), Vendors (status), Reviews (ratings)

**Approvals & Queues:**

- Product approvals
- Vendor onboarding
- Refund requests

---

## Security, Compliance & SRE

- **RBAC** via Auth; vendor‑scoped access tokens (embed `vendorId`).
- **OWASP** best practices; input validation in every service.
- **Idempotency** keys for `orders`, `payments`, `payouts`.
- **Webhooks**: signature verification, retries, poison‑queue handling.
- **PII/Data**: encrypt at rest (DB), at transit (TLS), mask in logs.
- **Backups**: PITR for Postgres; daily snapshots for Mongo.
- **Rate limiting** at gateway; WAF for bots.
- **Observability**:
  - Metrics SLOs: p95 latency per service, error rate < 1%
  - Tracing spans across gateway → services → DB
  - Alerts: payment failure spikes, low stock, 5xx bursts

---

## Testing Strategy

- **Contract tests** (OpenAPI schema, consumer‑driven)
- **Unit tests** per service (business logic)
- **Integration tests** (service + DB + broker)
- **E2E flows** (cart → checkout → payment → fulfillment)
- **Load tests** (catalog/search heavy; checkout peak)

**Data seeding:** factories for vendors/products/variants to simulate a real catalog.

---

## Deployment & Environments

- **Envs:** `dev` → `staging` → `prod`
- **Blue/Green or Rolling** deploys in K8s
- **Secrets:** Vault/SSM; never in git
- **Migrations:** Postgres via migration tool; Mongo migration scripts
- **Feature flags:** toggle risky features (pricing AI, new checkout)

**Disaster Recovery:** cross‑region DB replicas; restore runbooks tested quarterly.

---

## Config Matrix (.env)

- **Gateway:** `JWT_PUBLIC_KEY`, `RATE_LIMIT`, `ALLOWED_ORIGINS`
- **Auth:** `JWT_PRIVATE_KEY`, `REFRESH_TTL`, `PASSWORD_POLICY`
- **Catalog:** `MONGO_URI`, `IMAGE_BUCKET`, `MAX_IMAGES_PER_PRODUCT`
- **Inventory:** `DB_URI`, `RESERVATION_TTL_MINUTES`
- **Cart:** `REDIS_URL`, `CART_TTL_DAYS`
- **Order:** `DB_URL`, `ORDER_NO_PREFIX`
- **Payment:** `STRIPE_KEY`, `SSLCOMMERZ_STORE_ID`, `WEBHOOK_SECRET`
- **Shipping:** `CARRIER_KEYS_JSON`, `DEFAULT_ORIGIN`
- **Notification:** `SENDGRID_KEY|MAILGUN_KEY`, `SMS_PROVIDER_KEY`
- **AI:** `MODEL_REGISTRY_URL`, `FEATURE_STORE_URL`
- **Search:** `ELASTIC_URL`, `RELEVANCE_WEIGHTS_JSON`

---

## Future Enhancements Backlog

- **Wishlist Service**, **Gift Cards**, **Loyalty Points**
- **Multi‑warehouse** / store pickup
- **Vendor SLAs & penalties**
- **Price rules engine** (promotions/BOGO)
- **A/B testing** in AI recommender
- **Headless mobile app** (React Native) hitting same APIs

---

## Glossary

- **GMV:** Gross Merchandise Volume (sum of order totals before refunds)
- **AOV:** Average Order Value
- **SLA:** Service Level Agreement
- **PII:** Personally Identifiable Information

---

### Final Notes

- Start **MVP**: Auth, Vendor, Catalog, Inventory, Cart, Orders, Payment.
- Keep **events** clean and versioned.
- Add **AI/Search** once you have enough behavioral data.
- Ship fast, measure, iterate — but keep the foundation traditional & robust.

🟢 Step 0: Foundations
Pick stack & infra: Node.js/NestJS, MongoDB/Postgres, Redis, Kafka/RabbitMQ, Docker, K8s.

- Repo setup: mono-repo/poly-repo, CI/CD ready.

- API Gateway & Auth skeleton: JWT, RBAC setup.

- Observability: basic logging/tracing.

Goal: Environment ready, hello-world microservices chalate parbe.

🟢 Step 1: Identity & Vendor Onboarding
Auth Service: user register/login, JWT roles.

- User Profile Service: addresses, profile details.

- Vendor Service: vendor apply, KYC upload, admin approve.

- Goal: Vendor system live, basic RBAC working.

🟢 Step 2: Catalog & Media
Catalog Service: categories, brands, products, variants/SKUs.

- Media uploads: S3/Cloudinary integration.

- Product approval flow: admin approves vendor products.

- Goal: Vendor can submit products → admin approves → live.

🟢 Step 3: Inventory & Pricing
Inventory Service: stock, reservations, safety stock.

- Pricing: base price, compare-at price, tax class.

- Low stock alerts: send notifications.

- Goal: Stock accurate, checkout-ready.

🟢 Step 4: Cart & Coupons
Cart Service: per-user cart, items, quantities.

- Coupon Service: coupon codes, vendor/product/category scopes.

- Goal: Cart working + coupon applied correctly.

🟢 Step 5: Checkout, Orders & Payments
Order Service: order creation, vendor split.

- Payment Service: payment intents, webhooks.

- Inventory commit/release: reservation → commit on success.

- Goal: Customer can checkout fully, orders confirmed.

🟢 Step 6: Shipping & Fulfillment
Shipping Service: rates, tracking numbers, status updates.

- Order timeline: processing → shipped → delivered.

- Goal: Customers can track orders, vendors update shipments.

🟢 Step 7: Reviews & Notifications
Review Service: verified purchase reviews, moderation.

- Notification Service: emails, SMS, push notifications.

- Refund/Return basic: manual RMA.

- Goal: Reviews live, notifications sent, basic returns.

🟢 Step 8: Admin / Back-office

- Super Admin: vendors, products, orders, payouts, analytics.

- Vendor Admin: catalog, orders, stock alerts.

- Goal: Role-based dashboards working, analytics v1 ready.

🟢 Step 9: AI & Search Enhancements

- AI Service: recommendations, fraud scoring, inventory forecast.

- Search Service: semantic & typo-tolerant search.

- Goal: Personalized recommendations, smarter search, fraud flags.

🟢 Step 10: Analytics & Data Warehouse
Event ingestion → warehouse: GMV, AOV, cohorts.

- BI dashboards: Metabase/Superset or custom.

- Goal: Decision-grade metrics & reports.

🔹 Tips:
Always finish MVP flow first: Auth → Vendor → Catalog → Inventory → Cart → Checkout → Payment → Shipping.

- Add AI/Search only when enough data exists.

- Use message broker everywhere for async & decoupled communication.

- Deploy incrementally: dev → staging → prod.
