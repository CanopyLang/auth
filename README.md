# canopy/auth

Authentication helpers for Canopy applications: JWT decoding, OAuth2 PKCE flow, token lifecycle management, and route guards.

## Overview

`canopy/auth` provides the building blocks for authentication in single-page applications. It is deliberately not a full auth solution -- it handles the client-side concerns while leaving authorization decisions to the server.

### Design Principles

- **Server verifies, client displays**: JWT decoding extracts claims for UI/routing; signature verification happens server-side
- **PKCE by default**: OAuth2 Authorization Code with PKCE is the only recommended flow for SPAs
- **Tokens are opaque**: Wrapped in `AccessToken` and `RefreshToken` types to prevent misuse
- **State machine**: Authentication state transitions are explicit and type-safe
- **Storage agnostic**: Token persistence is configurable (localStorage, sessionStorage, memory-only)

## Modules

| Module | Description |
|--------|-------------|
| `Auth` | Core session state machine, opaque token types, expiry checks |
| `Auth.Jwt` | JWT decoding (header + payload extraction, no signature verification) |
| `Auth.Token` | Token storage, retrieval, refresh, and HTTP header helpers |
| `Auth.OAuth` | OAuth2 Authorization Code + PKCE flow helpers, provider presets |
| `Auth.Guard` | Protected route/view patterns with type-safe guard results |

## Quick Start

### Session State

```canopy
import Auth exposing (Session(..))

-- The session is a state machine
type Session user
    = Guest                          -- not authenticated
    | Authenticating                 -- auth flow in progress
    | Authenticated (AuthenticatedUser user)  -- authenticated with tokens
    | Expired (AuthenticatedUser user)        -- token expired

-- Query the session
Auth.isAuthenticated session       -- Bool
Auth.getUser session               -- Maybe user
Auth.getAccessToken session        -- Maybe AccessToken
Auth.isExpired now session         -- Bool
```

### JWT Decoding

```canopy
import Auth.Jwt as Jwt

-- Decode a JWT payload
case Jwt.decodePayload tokenString of
    Ok payload ->
        -- payload.sub, payload.exp, payload.claims, etc.
        ...

    Err err ->
        -- Jwt.jwtErrorToString err
        ...

-- Decode with a custom decoder
Jwt.decodePayloadWith userDecoder tokenString

-- Check expiry
Jwt.isExpired now payload
Jwt.isExpiredWithBuffer 300 now payload
```

### OAuth2 PKCE Flow

```canopy
import Auth.OAuth as OAuth

-- Configure a provider
config =
    OAuth.google
        { clientId = "your-client-id"
        , redirectUri = "http://localhost:8000/callback"
        , scopes = [ "openid", "profile", "email" ]
        }

-- Build the authorization URL
url = OAuth.authorizationUrl config authRequest

-- Parse the redirect response
case OAuth.parseRedirect redirectUrl of
    Ok response ->
        case OAuth.validateState authRequest response of
            Ok validResponse ->
                -- Exchange code for tokens
                ...
            Err OAuth.StateError ->
                -- CSRF protection triggered
                ...
    Err (OAuth.AuthorizationDenied reason) ->
        ...
```

### Route Guards

```canopy
import Auth.Guard as Guard

-- Require authentication
Guard.requireAuth
    { session = model.session
    , loginUrl = "/login"
    , page = \user -> DashboardPage user
    }

-- Require a specific role
Guard.requireRole
    { session = model.session
    , loginUrl = "/login"
    , predicate = \user -> user.isAdmin
    , page = \user -> AdminPage user
    }

-- View helpers
Guard.whenAuthenticated model.session
    (\user -> div [] [ text ("Hello, " ++ user.name) ])
    (button [ onClick Login ] [ text "Sign in" ])
```

### Token Management

```canopy
import Auth.Token as Token

-- Build Authorization header
Token.authHeader accessToken  -- Http.Header

-- Decode token response from server
Token.tokenResponseDecoder    -- Json.Decode.Decoder TokenResponse

-- Parse scopes
Token.parseScopes (Just "openid profile")  -- [ "openid", "profile" ]
```

## Provider Presets

Built-in configurations for common OAuth2 providers:

- `Auth.OAuth.google` -- Google OAuth2
- `Auth.OAuth.github` -- GitHub OAuth2
- `Auth.OAuth.microsoft` -- Microsoft Azure AD
- `Auth.OAuth.auth0` -- Auth0 (requires domain and audience)

## Security Notes

1. **XSS**: Tokens in localStorage are accessible to JavaScript. Use `MemoryOnly` storage for sensitive applications.
2. **CSRF**: The OAuth2 `state` parameter prevents CSRF attacks. Always validate it with `OAuth.validateState`.
3. **No signature verification**: JWT decoding in this library is for display/routing only. All authorization must happen server-side.
4. **PKCE**: Required for SPAs because they cannot securely store a client secret.

## Dependencies

- `canopy/core`, `canopy/json`, `canopy/time`, `canopy/url`, `canopy/http`
