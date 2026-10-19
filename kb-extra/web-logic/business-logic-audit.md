# Web business-logic & authorization audit checklist

For flaws that have **no payload to copy** — the bug is in the *workflow*, not a string. These cover xbow's `business_logic` + `privilege_escalation` + `idor` + `race_condition` cluster. Method: enumerate every state-changing action, then attack the *assumptions* the app makes about order, ownership, price, and identity.

## 1. Authorization matrix (IDOR / horizontal & vertical priv-esc)
Build a grid: **{roles/users} × {objects/actions}**, then test every cell.
- **Horizontal (IDOR)**: as user A, take every request that references an object you own (`/order/1042`, `?user_id=`, `account`, `uuid`, filename, JWT `sub`) and swap the identifier for B's. Try: sequential IDs, decoded/re-encoded IDs, GUIDs from other responses, negative/zero, arrays (`id[]=1&id[]=2`), and IDs in *nested* JSON or headers. Fuzz any value that "looks like an ID" (0926-3 hint).
- **Vertical**: replay an admin-only action (from docs/JS/`/api` routes you can enumerate) as a low-priv user. Check: does the server re-check role, or trust a client field (`role=user`, `isAdmin=false`, a hidden form field, a JWT claim you can tamper — see JWT/`flask-unsign`)?
- **Missing function-level access control**: admin endpoints reachable directly (`/admin/…`) without UI links; different HTTP method (`GET` blocked but `POST`/`PUT` allowed — method tamper); `/api/v1` vs `/api/v2` differing checks.
- **Mass assignment**: POST extra fields the UI never sends (`role`, `is_admin`, `balance`, `verified`, `price`) — frameworks that bind request body → model object grant them.

## 2. Price / amount / quantity tampering
- Change price, quantity, currency, or total in the request even if the UI fixes them. **Negative quantity** → credit; **negative price**; huge quantity → integer overflow / free.
- Apply a discount/coupon, then change the item — is the discount re-validated?
- Currency confusion (pay in a weaker currency), rounding (fractional cents), tax/shipping fields set to negative.

## 3. Replay / coupon / token reuse
- Reuse a one-time coupon, gift card, OTP, CSRF token, or nonce more than once (server must invalidate on first use — often doesn't).
- Replay a signed request/receipt; reuse a password-reset or email-verification token; use a token issued for account A on account B.

## 4. Race conditions (TOCTOU)
- Fire N concurrent requests to a "check-then-act" flow: redeem the same coupon/balance/gift card in parallel (limit checked before decrement) → spend once, credited N times.
- Concurrent signup with same username; simultaneous withdrawals exceeding balance; parallel "apply once" actions.
- Tooling: send 20–100 requests with near-simultaneous dispatch (threads / HTTP/2 single-packet). Look for more successes than the limit allows.

## 5. Workflow / state-machine bypass
- Skip steps: go straight to the "confirm/checkout/success" endpoint without the prerequisites (payment, verification). Access step N without completing N-1.
- Re-order steps, repeat a step, or resume a cancelled/expired flow.
- Force positive outcomes: set a `status`/`step`/`paid=true` field the server should own.
- 2FA/verification bypass: is the "verified" flag client-controlled or the code brute-forceable/rate-limit-free?

## 6. Registration / account
- Default / weak credentials (xbow's frequent `default_credentials`): try `admin/admin`, product defaults, `admin@<domain>`, seed users from source/`.env`/fixtures.
- Username collision / unicode homoglyph / case (`Admin` vs `admin`) to impersonate.
- Self-register a privileged role if the field is bindable.

## How to work it
1. **Crawl & enumerate** every endpoint and parameter (spider, JS files, `/api` docs, `robots.txt`, `swagger`/`graphql` introspection). Business-logic bugs live in endpoints the UI hides.
2. **Two accounts** (or two roles) — most auth bugs need an A/B comparison.
3. **Diff responses** across roles/identities to spot missing checks (200 vs 403 vs "silently returns B's data").
4. This is **multi-step** — model the flow (cart→coupon→checkout) and drive it programmatically; the bug is usually in the *transition*, and finding it often needs persistent multi-request interaction, not a single payload.
