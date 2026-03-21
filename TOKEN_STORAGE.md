# Token Storage in canopy/auth

This document explains how `canopy/auth` stores authentication tokens in the browser, the security tradeoffs of each strategy, and the recommended configuration for common application patterns.

## Storage Strategies

The package exposes three storage strategies, selected per token type when configuring the auth module:

### `MemoryOnly`

The token is held exclusively in JavaScript heap memory inside the Canopy runtime. It is never written to any browser storage API.

- Survives page re-renders and in-app navigation.
- Lost on page reload, tab close, or browser restart — the user must re-authenticate.
- Not accessible to other tabs or windows.

### `LocalStorage String`

The token is persisted to `window.localStorage` under the supplied key name.

```canopy
Auth.configure
    { accessToken = MemoryOnly
    , refreshToken = LocalStorage "app.refresh_token"
    }
```

- Persists indefinitely across reloads, tab closes, and browser restarts until explicitly cleared.
- Accessible to all same-origin tabs and windows simultaneously.
- Readable by any JavaScript executing on the same origin, including injected scripts from XSS attacks.

### `SessionStorage String`

The token is persisted to `window.sessionStorage` under the supplied key name.

```canopy
Auth.configure
    { pkceVerifier = SessionStorage "app.pkce_verifier"
    }
```

- Scoped to the current browser tab; other tabs cannot read it.
- Cleared automatically when the tab is closed.
- Like LocalStorage, readable by any JavaScript on the same origin.

---

## Security Tradeoffs

| Strategy | XSS-safe | Survives reload | Survives tab close | Shared across tabs |
|---|---|---|---|---|
| `MemoryOnly` | Yes | No | No | No |
| `LocalStorage` | No | Yes | Yes | Yes |
| `SessionStorage` | No | Yes | No | No |

XSS-safe means the token cannot be exfiltrated by a script injected into the page. Memory-only tokens are never serialised to a storage API, so an XSS attacker running `localStorage.getItem(...)` or `sessionStorage.getItem(...)` cannot retrieve them.

---

## Why Access Tokens Are Memory-Only by Default

Access tokens are short-lived — typically 5 to 60 minutes. Their primary threat model is XSS: an attacker who can run arbitrary JavaScript on your origin can steal tokens and make authenticated API requests before the token expires.

Persisting an access token to LocalStorage increases XSS attack surface: the token survives the user's current session and is readable by any script on the origin at any future point. Because access tokens expire quickly, there is no meaningful UX benefit to persistence — the application will obtain a fresh token from the refresh flow on the next load anyway.

For these reasons, `MemoryOnly` is the default for access tokens, and the package does not expose a LocalStorage option for them.

---

## Refresh Tokens in LocalStorage

Refresh tokens are long-lived (hours to days) and are used to obtain new access tokens without requiring the user to log in again. Storing them in LocalStorage is an accepted tradeoff for applications that prioritise seamless sessions over maximum XSS hardening.

If you store refresh tokens in LocalStorage, you must implement CSRF protection:

- Validate the `Origin` or `Referer` header on token-refresh endpoints.
- Bind refresh tokens to a client fingerprint (e.g., a rotating cookie-bound nonce) on the server side.
- Rotate refresh tokens on every use and invalidate the old token immediately.

Without these controls, an attacker who exfiltrates a LocalStorage refresh token can silently re-authenticate indefinitely even after the access token expires.

---

## QuotaExceededError Handling

`window.localStorage` and `window.sessionStorage` have per-origin quotas (typically 5–10 MB). If a write fails with `QuotaExceededError`, `canopy/auth` catches the error rather than propagating it as an unhandled exception. The affected token's storage strategy is downgraded to `MemoryOnly` for the remainder of the session, and the application continues to function.

This means storage failures are silent from the application's perspective. If you rely on token persistence across reloads, monitor for unexpected re-authentication prompts in environments with restricted storage — private browsing modes and some enterprise browser policies may impose stricter quotas.

---

## Recommended Pattern

| Token | Strategy | Rationale |
|---|---|---|
| Access token | `MemoryOnly` | Short-lived; XSS exposure outweighs any persistence benefit |
| Refresh token | `LocalStorage "app.refresh_token"` | Long-lived sessions require persistence; mitigate with CSRF controls |
| PKCE code verifier | `SessionStorage "app.pkce_verifier"` | Only needed for the duration of one authorization flow; tab-scoped is sufficient |

```canopy
Auth.configure
    { accessToken  = MemoryOnly
    , refreshToken = LocalStorage "app.refresh_token"
    , pkceVerifier = SessionStorage "app.pkce_verifier"
    }
```

This configuration gives you persistent sessions via the refresh token while keeping the short-lived access token out of any storage API that a script could query.
