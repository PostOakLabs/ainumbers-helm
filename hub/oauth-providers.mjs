// Named-provider OAuth presets (HELM-P2-H9b, DEC-5 increment). Phase-1's
// oauth-pkce.mjs startFlow() is already fully provider-agnostic — it takes
// any authorizationEndpoint/tokenEndpoint/clientId/scopes and runs the
// RFC 8252 loopback + PKCE flow (shipped H5, R1/SEC-reviewed). This module
// adds nothing new to that mechanism; it supplies the ONE named preset the
// row asks for (GitHub) so callers don't hand-type endpoints, and gives the
// contract test a real provider's exact endpoint/scope shape to exercise.
//
// No openid-client dependency: this is a zero-dep repo (D11/D2 — see
// package.json), and the hand-rolled PKCE loopback already passed its own
// security review, so adopting a library here would be a re-platform for no
// safety gain, not the "MVP surface" the spec asks for.
export const GITHUB = {
  provider: "github",
  authorizationEndpoint: "https://github.com/login/oauth/authorize",
  tokenEndpoint: "https://github.com/login/oauth/access_token",
  revocationEndpoint: null, // GitHub has no RFC 7009 revocation endpoint — app "Revoke" is account-side only
  defaultScopes: ["repo"],
};

// Builds the exact params object oauth-pkce.mjs's startFlow() expects.
// Endpoints are overridable ONLY for tests (a sandboxed runner cannot reach
// github.com) — production callers omit authorizationEndpoint/tokenEndpoint
// and get the real GitHub URLs above.
export function beginGithubFlowParams({ clientId, scopes = GITHUB.defaultScopes, authorizationEndpoint, tokenEndpoint }) {
  if (!clientId) throw new Error("oauth-providers: github requires a clientId");
  return {
    provider: GITHUB.provider,
    authorizationEndpoint: authorizationEndpoint ?? GITHUB.authorizationEndpoint,
    tokenEndpoint: tokenEndpoint ?? GITHUB.tokenEndpoint,
    revocationEndpoint: GITHUB.revocationEndpoint,
    clientId,
    scopes,
  };
}
