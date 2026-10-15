# Proton Pass Browser Vault Plugin for Hermes

A standalone Hermes login backend that exposes explicitly allowlisted Proton Pass login items through Hermes Browser Vault. It is intentionally maintained outside the Hermes source tree, so Hermes updates cannot overwrite the plugin package.

## Security and privacy

- Credentials are obtained through Hermes's profile-scoped secret API (`agent.secret_scope`), never from `.env`, Hermes `auth.json`, macOS Keychain, browser profiles, or Proton vendor session files.
- Each metadata or password operation creates a private temporary Proton CLI session, authenticates for that operation, and removes the session afterward. No persistent Proton CLI session is reused.
- There is no default vault scope, including no implicit `Hermes Access` vault. With neither nonempty exact-item scope nor explicit vault names, listing and resolution return nothing without contacting Proton.
- Only exact configured `share_id`/`item_id` pairs are eligible when `allowed_vault_names` is omitted or empty. Explicit vault names opt into broader access; an item allowlist, when supplied, further restricts it. An empty `allowlisted_items: []` denies all items even with vault names.
- Signed handles are checked against current scope before provider access; previously issued handles cannot retain access to items whose scope has been revoked.
- Saved URLs are normalized to exact browser origins and handles are signed. Metadata is revalidated before a password is resolved, and origin changes fail closed.
- Password material is passed only through Hermes's protected Browser Vault fill boundary. It is not printed in plugin diagnostics, test fixtures, manifests, or logs.
- The plugin invokes a user-installed `pass-cli` executable and makes network requests through that CLI during authentication and metadata access. It does not collect telemetry or run background processes.

## Requirements

- **Unreleased core dependency:** Hermes must include the generic `register_login_backend` integration from [core PR #119863](https://github.com/NousResearch/hermes-agent/pull/119863) and the profile-scoped secret API. Compatibility was tested against PR head `0741d45269fc11c40548757ce7bb38d417c62ee5`. The backend implements that API's `is_available(cls, config)` contract. No released Hermes version floor is claimed; installation on a release without this integration is not supported.
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

`allowed_vault_names: []` plus a nonempty `allowlisted_items` is the recommended exact-item mode. Omitting both keys, setting both to empty lists, or using `allowlisted_items: []` grants no access. For explicit vault-wide access, set e.g. `allowed_vault_names: ["Hermes Access"]` and omit `allowlisted_items`; supplying both scopes restricts results to their intersection. Vault names must be exact nonempty strings, without surrounding whitespace. The plugin does not read passwords merely to enumerate metadata.

These settings belong under `vault.protonpass`, not `plugins.entries.proton-pass.config`. Enable the directory plugin separately using Hermes's plugin manager.

## Development and verification

Use a checkout containing the required core API and a prepared test interpreter. Run the checkout's canonical `scripts/run_tests.sh` against this plugin's absolute `tests/` path (it supports external test files). Keep `HOME`, `HERMES_HOME`, `HERMES_RUNTIME_DIR`, and test temporary files in disposable scratch directories; the runner scrubs the environment, so configure isolation and the checkout import path in the `HERMES_PYTHON` wrapper. Do not install dependencies into an active Hermes runtime merely to validate this plugin.

Run `hermes plugins validate /path/to/proton-pass-hermes-plugin --install-deps --json` using that same isolated core environment. Validation alone does not exercise activation: `tests/test_scope_and_discovery.py` also copies the plugin into a synthetic profile and exercises real directory discovery, availability, default-off/opt-in routing, and unload.

The test suite uses only local synthetic CLI fixtures and redacted sentinel values. It does not perform live Proton authentication.

## Catalog submission

This package is designed for the Hermes plugin catalog's standalone-plugin workflow. A catalog entry must be added by pull request to the Hermes repository and must pin the public plugin repository to a full commit SHA. The catalog entry should disclose the `pass-cli` subprocess/network behavior and the Hermes-managed secret requirement. No catalog entry or public repository URL is claimed by this standalone working directory.
