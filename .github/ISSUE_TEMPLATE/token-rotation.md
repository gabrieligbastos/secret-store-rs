## Rotate the crates.io publish token

The `CARGO_REGISTRY_TOKEN` GitHub Actions secret is expiring soon (see issue title for exact date).

### Steps to rotate

1. Go to https://crates.io/settings/tokens → **New Token**
   - Name: `secret-store-rs-publish`
   - Scopes: Publish new crates + Publish updates
   - Expiry: 1 year from today
2. Copy the new token (shown only once).
3. Go to **Settings → Secrets and variables → Actions → `CARGO_REGISTRY_TOKEN`** → Update secret.
4. Update the **`CARGO_REGISTRY_TOKEN_EXPIRES`** repository variable to the new expiry date (`YYYY-MM-DD`):
   Settings → Secrets and variables → Actions → **Variables** tab → `CARGO_REGISTRY_TOKEN_EXPIRES`.
5. Close this issue.

_Opened automatically by the [token-rotation workflow](../../actions/workflows/token-rotation.yml)._
