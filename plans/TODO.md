# canopy/auth — TODO

## Status: Has Critical Bug (v1.0.0)

JWT decoding, token lifecycle, OAuth2 PKCE flow, session state, auth guards.

---

## Critical: Bugs to Fix

- [ ] **`neverMsg` in Token.can (line ~162-163) is infinitely recursive** — `neverMsg msg = neverMsg msg`. This will crash at runtime when token refresh is attempted. Fix with proper Never elimination or restructure the API.

---

## Missing Core Features

- [ ] `logout : Session -> (Session, Cmd msg)` — No logout function exists
- [ ] PKCE challenge generation — `generateCodeVerifier` and `generateCodeChallenge` are referenced in OAuth but not implemented
- [ ] Token exchange — function to exchange authorization code for tokens (the OAuth code flow completion step)
- [ ] Session timeout — auto-expire session after inactivity
- [ ] Refresh token rotation
- [ ] Multi-tab session sync (via canopy/broadcast-channel)
- [ ] Remember me — persistent vs session-only token storage

---

## Features to Add

- [ ] Social login helpers beyond the 4 presets (Google, GitHub, Microsoft, Auth0)
- [ ] SAML authentication support
- [ ] MFA/2FA flow support
- [ ] Device authorization grant (for TV/IoT)
- [ ] Token introspection endpoint support

---

## Test Improvements

- [ ] Good coverage (5 files, 2006 lines) — add regression test for neverMsg crash
- [ ] Add integration test for full OAuth flow
