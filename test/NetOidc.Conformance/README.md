# NetOidc conformance host

An OpenID Provider built on NetOidc and configured for the
[OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite). It runs the
suite's test plans locally in Docker, which is how NetOidc checks itself against the
certification profiles before submitting to the hosted suite.

## Running

Prerequisites: Docker, the .NET 10 SDK, git, and Python 3 with `httpx` and `pyparsing`
(`python -m pip install httpx pyparsing`).

```bash
cd test/NetOidc.Conformance
./run-conformance.sh oidcc                # every OpenID Connect OP plan
./run-conformance.sh fapi2                # FAPI 2.0 Security Profile (DPoP and mTLS)
./run-conformance.sh fapi2-ms             # FAPI 2.0 Message Signing
./run-conformance.sh fapi1                # FAPI 1.0 Advanced
./run-conformance.sh fapi-ciba            # FAPI-CIBA (poll and ping)

# One plan only: "<plan[variants]>:<configuration file>"
./run-conformance.sh oidcc "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]:oidcc-static.json"
```

The script:

1. clones the suite (`SUITE_TAG`, default `release-v5.3.1`) into `.suite/` and starts its
   prebuilt images (MongoDB, nginx, server) with Docker Compose;
2. starts this host in the Production environment on `https://host.docker.internal:8990`, with a
   self-signed TLS certificate and freshly generated keys;
3. lets the host write the plan configurations into the suite's `scripts/` directory (they
   contain the generated client keys and certificates);
4. runs the plans with the suite's `run-test-plan.py` and exports the results to `results/`.

Profiles can run concurrently with distinct `OP_URL` ports, `ALIAS` values and `CONFIGURATION`
build configurations (a running host locks its build output). The host trusts the local suite's
self-signed certificate for the suite's host only. Set `KEEP_SUITE=1` to leave the suite running; its UI is at
<https://localhost.emobix.co.uk:8443> (that name resolves to 127.0.0.1).

## What the host does

| Page | Behaviour |
|------|-----------|
| `/account/login` | Signs in `conformance-user` on submit, with `auth_time` now and `acr` = the first requested `acr_values`; **Cancel** reports `access_denied` through `InteractionDenialService` |
| `/account/consent` | Shows the client's name, logo, policy and terms; records consent |
| `/account/logout` | Logout confirmation |
| `RenderErrorPage` | A "NetOidc error" page for errors that cannot go back to the client |

The suite drives these pages with the `browser` instructions in each configuration
(`SuiteBrowser.cs`). Tests that ask for a screenshot (prompt=login, error pages, logos) are
marked "review": the automation uploads a placeholder, and a human checks the screenshot before
certification.

## Profiles

| Profile | OP configuration | Plans |
|---------|------------------|-------|
| `oidcc` | Static and dynamic clients, all response types, logout (RP-initiated, front- and back-channel) | Basic, Implicit, Hybrid, Form Post, Config, Dynamic, RP-Initiated, Front-Channel and Back-Channel Logout |
| `fapi2` | FAPI 2.0 Security Profile, PAR, DPoP and mTLS | FAPI 2.0 SP Final: private_key_jwt + DPoP, private_key_jwt + mTLS, mTLS + mTLS |
| `fapi2-ms` | FAPI 2.0 Message Signing: signed requests, JARM | FAPI 2.0 MS Final: private_key_jwt + DPoP |
| `fapi1` | FAPI 1.0 Advanced: request objects or PAR, hybrid or JARM, mTLS-bound tokens | FAPI 1 Advanced Final: private_key_jwt by value, mTLS + PAR + JARM |
| `fapi-ciba` | FAPI-CIBA: signed backchannel requests, mTLS-bound tokens; a simulated device approves after 10 s | FAPI-CIBA ID1: private_key_jwt, poll and ping |

`ConformanceProfiles.cs` holds each OP configuration and its plan configurations. To add a
variant, add the plan to `PLANS` in `run-conformance.sh` and, if it needs different clients,
a configuration to the profile.

## Results

The latest local results, including known warnings and their reasons, are recorded in
[docs/CONFORMANCE.md](../../docs/CONFORMANCE.md). Known, explained deviations for a profile go in
`expected-failures-<profile>.json` (suite format), so that a full profile run fails only on
regressions. The runner still exits non-zero when a module needs a screenshot review or is
interrupted by design (e.g. the CIBA "user rejects" test).
