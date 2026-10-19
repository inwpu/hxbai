# Default & Product-Derived Credentials (general TTP)

> General, public pentest knowledge — a methodology + well-known default-credential pointers for **common
> off-the-shelf products**. NOT specific to any one target/challenge; contains no target's actual credentials.
> Use it to turn "I fingerprinted an internal service to a product" into "try that product's own defaults first".

## When this applies
A service that requires authentication (SSH, an admin/management panel, a login form, a DB or management port)
sits on a host you have fingerprinted to a **specific product / vendor / product-line** — very often an
**internal host reached by pivoting** from an entry foothold. Before (or alongside) a generic wordlist brute,
the product's **own** well-known/default credentials and **name-derived guesses** are a first-class path.

## Method
1. **Fingerprint the product**: banner/version, HTTP title/`Server`/favicon, login-page branding, error pages,
   default file paths, port conventions. Pin it to a product name (and ideally version) before guessing creds.
2. **Try the product's documented defaults first.** Most COTS products ship well-known default accounts; these
   are published in the vendor docs and in default-credential lists (e.g. SecLists `Passwords/Default-Credentials/`,
   the `default-credentials` / `changeme`-style datasets). Look them up: `kb search <product> default credentials`.
3. **Build name-derived guesses yourself** (when no documented default is found): the product/vendor/product-line
   name and its common romanizations, as username and/or password, with trivial variants (vendor as user +
   vendor/`123456`/`admin`/`password`/`<vendor>@<year>` as password; `admin`/`root`/`administrator` as user).
   Product software very commonly ships an account named after itself.
4. **Spray at a LOW rate** (respect lockout + the engagement rate discipline): a small, ordered candidate list
   (documented defaults → name-derived → top generic) beats a blind large wordlist and avoids lockout/alerts.
5. **On an internal product panel/DB**, the same applies — management consoles (CI, DB admin, OA/ERP/CMS,
   monitoring, container/orchestration dashboards) are routinely left on defaults inside the perimeter.

## Common product-family default-account conventions (illustrative, verify per product)
- Web/app frameworks & CMS: `admin/admin`, `admin/password`, `admin/<productname>`, install-wizard leftovers.
- DB & mgmt: `root` (empty / `root` / `password`), `sa` (empty / weak), `postgres/postgres`, `redis` (no auth).
- Devices/appliances/monitoring: vendor-name account, `admin/admin`, documented factory defaults.
- OA/ERP/collaboration suites: an account named after the product/vendor is extremely common; check vendor docs.

## Red line
This is the **method** (identify product → try its defaults → name-derived → generic, low-rate). The actual
credential that works on any specific host is discovered by **you** against that host — never assume a listed
convention is the answer; confirm by real auth output.
