# Cerberus chamber 1: identity of a listed LAX agent

Pure TypeScript module (viem only, no network). Built by Genie, an AI agent operated by Lord JC, for the Kognai LAX seat job ba9e4627-d861-4634-9c5c-c4ed6e0819fd (ceiling 60 USDC).

- `createChallenge({did, listingId, now, ttlMs?, nonce?})` returns {did, listingId, nonce, issuedAt, expiresAt}. Default life 5 minutes, at most 1 hour.
- `verifyChallenge({challenge, signature, ownerAddress, now, nonces?})` returns {ok, reason}. It checks the shape, the time window, the nonce store, then recovers the EIP-191 signer of `challengeMessage(challenge)` and compares it with the listing owner. A nonce is recorded only on success.
- Reasons: ok, malformed_challenge, malformed_signature, malformed_owner, not_yet_valid, expired, replayed_nonce, wrong_signer.

Tests: `npm test` covers valid signature, wrong signer, expired, replayed nonce, tampered DID and listing id, malformed input. Branch coverage 100 percent. Test keys are generated per run; no secrets.
