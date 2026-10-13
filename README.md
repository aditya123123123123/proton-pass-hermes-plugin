# Proton Pass Browser Vault Plugin for Hermes

A standalone Hermes login backend that exposes explicitly allowlisted Proton Pass login items through Hermes Browser Vault. It is intentionally maintained outside the Hermes source tree, so Hermes updates cannot overwrite the plugin package.

## Security and privacy

- Credentials are obtained through Hermes's profile-scoped secret API (`agent.secret_scope`), never from `.env`, Hermes `auth.json`, macOS Keychain, browser profiles, or Proton vendor session files.
- Each metadata or password operation creates a private temporary Proton CLI session, authenticates for that operation, and removes the session afterward. No persistent Proton CLI session is reused.
- Only exact configured `share_id`/`item_id` pairs are eligible when `allowed_vault_names` is empty. Vault-wide access is not enabled by default.
- Saved URLs are normalized to exact browser origins and handles are signed. Metadata is revalidated before a password is resolved, and origin changes fail closed.
- Password material is passed only through Hermes's protected Browser Vault fill boundary. It is not printed in plugin diagnostics, test fixtures, manifests, or logs.
- The plugin invokes a user-installed `pass-cli` executable and makes network requests through that CLI during authentication and metadata access. It does not collect telemetry or run background processes.

## Requirements

- Hermes with the generic `register_login_backend` integration and profile-scoped secret API.
- Proton Pass `pass-cli` installed separately from its official distribution.
- A Hermes-managed secret named `PROTON_PASS_PERSONAL_ACCESS_TOKEN`.
- A profile-relative connection file containing only nonsecret CLI metadata, for example:

```json
{"binary": "/absolute/path/to/pass-cli"}
```

Do not put a PAT, password, session token, or vendor session data in the connection file.

## Configuration

The plugin is disabled by default. Enable it only after configuring exact scope:

```yaml
vault:
  protonpass:
    enabled: true
    connection_file: proton-pass/connection.json
    allowed_vault_names: []
    allowlisted_items:
      - share_id: "<exact-share-id>"
        item_id: "<exact-item-id>"
```

`allowed_vault_names: []` plus `allowlisted_items` is the recommended exact-item mode. Use vault names only when the broader vault scope is explicitly intended. The plugin does not read passwords merely to enumerate metadata.

## Development and verification

From the plugin directory, with a Hermes checkout available for imports:

```bash
PYTHONPATH=/path/to/hermes-agent pytest -o addopts= -q
hermes plugins validate /path/to/proton-pass-hermes-plugin --install-deps
```

The test suite uses only local synthetic CLI fixtures and redacted sentinel values. It does not perform live Proton authentication.

## Catalog submission

This package is designed for the Hermes plugin catalog's standalone-plugin workflow. A catalog entry must be added by pull request to the Hermes repository and must pin the public plugin repository to a full commit SHA. The catalog entry should disclose the `pass-cli` subprocess/network behavior and the Hermes-managed secret requirement. No catalog entry or public repository URL is claimed by this standalone working directory.
