# OpenID conformance results

NetOidc is tested against the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
(release `v5.3.1`), run locally in Docker with `test/NetOidc.Conformance` (see its
[README](../test/NetOidc.Conformance/README.md)). These are **local results, not a certification**:
certification needs a run against the hosted suite with a publicly reachable deployment, the
screenshots marked "review" checked, and the self-attestations below.

Latest run: 2026-09-30, branch `release/1.0`.

## Results

"Review" modules passed their automated checks and ask for a screenshot (error pages, logout
pages, logos), which the automated run uploads as a placeholder. "Skipped" modules test optional
features the configuration does not offer.

| Plan | Variant | Passed | Review | Skipped | Warnings | Failures |
|------|---------|-------:|-------:|--------:|---------:|---------:|
| OIDC Basic | static client, discovery | 29 | 3 | 2 | 1¹ | 0 |
| OIDC Implicit | static client, discovery | 43 | 6 | 4 | 1¹ | 0 |
| OIDC Hybrid | static client, discovery | 78 | 9 | 6 | 3¹ | 0 |
| OIDC Form Post (Basic) | static client, discovery | 29 | 3 | 2 | 1¹ | 0 |
| OIDC Config | | 1 | | | | 0 |
| OIDC Dynamic | `code`, private_key_jwt | 11 | 6 | 5 | | 1² |
| RP-Initiated Logout | `code`, static client | 3 | 8 | | | 0 |
| Front-Channel RP-Initiated Logout | `code`, static client | 2 | | | | 0 |
| Back-Channel RP-Initiated Logout | `code`, static client | 2 | | | | 0 |
| FAPI 2.0 Security Profile | private_key_jwt + DPoP | 55 | | | | 1³ |
| FAPI 2.0 Security Profile | private_key_jwt + mTLS | 47 | | | | 0 |
| FAPI 2.0 Security Profile | mTLS + mTLS | 37 | | | | 0 |
| FAPI 2.0 Message Signing | private_key_jwt + DPoP, signed requests, JARM | 70 | | | | 0 |
| FAPI 1.0 Advanced | private_key_jwt, request object by value | 42 | 3 | | | 0 |
| FAPI 1.0 Advanced | mTLS, PAR, JARM | 49 | | | | 0 |
| FAPI-CIBA | private_key_jwt, poll | 34 | | | | 1⁴ |
| FAPI-CIBA | private_key_jwt, ping | 39 | | | | 1⁴ |

1. `oidcc-userinfo-post-body`: UserInfo accepts the access token only in the `Authorization`
   header (REMEDIATION_PLAN P2.4). Form-body tokens (RFC 6750 §2.2) are optional; this is a
   deliberate security choice.
2. `oidcc-server-rotate-keys`: needs a person to rotate the OP's keys between two JWKS fetches.
   Rotation is supported (`notBefore`/`notAfter`, `IKeyStore`; see [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md))
   and is self-attested for certification.
3. `fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri`: the suite could not
   reach the OP ("network is unreachable" between the Docker container and the host) before the
   test started. This Docker Desktop glitch recurred a few times across runs, on different modules;
   each of those modules passes on rerun.
4. `fapi-ciba-id1-user-rejects-authentication`: needs a person to refuse on the authentication
   device. The harness's simulated device always approves; hosts refuse with
   `ICibaService.CompleteAsync(authReqId, approve: false)`.

## Defects the suite found

Running the suite found these defects in NetOidc, all fixed with regression tests
(`ConformanceSuiteFindingsTests`, `RequestUriAndKeyRotationTests`, `SecurityReviewTests`):

- CIBA used the wrong grant type URN (`urn:ietf:params:oauth:grant-type:ciba` instead of
  `urn:openid:params:grant-type:ciba`).
- Authorization errors ignored the requested `response_mode`, lacked `iss` (RFC 9207 §2), and
  were never JARM-wrapped.
- `request_uri` by reference and relying-party key rotation via `jwks_uri` were missing (both
  required by the Dynamic profile); `policy_uri`/`tos_uri` were dropped from registrations.
- `error_description: null` was written into error bodies; a missing `code_verifier` was
  `invalid_request` instead of `invalid_grant`.
- DPoP authorization-code binding (`dpop_jkt`, RFC 9449 §10) was missing.
- FAPI 1.0 Advanced issued unbound tokens and lacked `s_hash`; the FAPI profiles accepted RS256
  and request objects without `nbf`/`exp` limits; response types outside a profile were
  `unauthorized_client` instead of `unsupported_response_type`, also at the PAR endpoint.
- Request objects nesting `request`/`request_uri` were accepted.
- Expired device codes and CIBA requests returned `invalid_grant` instead of `expired_token`.
- The FAPI-CIBA profile validator demanded PAR, so a valid FAPI-CIBA provider refused to start.
- `x-fapi-interaction-id` was not returned by the UserInfo resource endpoint.
- Hosts had no way to report that the End-User cancelled (`InteractionDenialService`).
- Request objects without `exp` were refused outside FAPI (OIDC Core §6.1 does not require it).
- A logout without a redirect ended in an empty 204; the front-channel page relied on JavaScript
  to continue.

## Reproducing

```bash
cd test/NetOidc.Conformance
./run-conformance.sh oidcc        # OpenID Connect plans
./run-conformance.sh fapi2        # FAPI 2.0 Security Profile
./run-conformance.sh fapi2-ms     # FAPI 2.0 Message Signing
./run-conformance.sh fapi1        # FAPI 1.0 Advanced
./run-conformance.sh fapi-ciba    # FAPI-CIBA
```

Run profiles one at a time; concurrent runs need distinct `OP_URL` ports and `ALIAS` values.
