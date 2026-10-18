import { recoverMessageAddress } from 'viem';
import type { Challenge, NonceStore, VerifyResult } from './types.js';
import {
  DEFAULT_TTL_MS, MAX_TTL_MS, challengeMessage, isAddress, isChallenge, isDid, isListingId, isNonce, isSignature,
} from './rules.js';

export type { Challenge, NonceStore, VerifyResult, VerifyReason } from './types.js';
export { challengeMessage } from './rules.js';

const randomNonce = (): string => {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
};

export function createChallenge(input: {
  did: string;
  listingId: string;
  now: Date;
  ttlMs?: number;
  nonce?: string;
}): Challenge {
  const ttl = input.ttlMs ?? DEFAULT_TTL_MS;
  if (!isDid(input.did)) throw new Error('invalid did');
  if (!isListingId(input.listingId)) throw new Error('invalid listing id');
  if (!Number.isInteger(ttl) || ttl <= 0 || ttl > MAX_TTL_MS) throw new Error('invalid ttl');
  const nonce = input.nonce ?? randomNonce();
  if (!isNonce(nonce)) throw new Error('invalid nonce');
  return {
    did: input.did,
    listingId: input.listingId,
    nonce,
    issuedAt: input.now.toISOString(),
    expiresAt: new Date(input.now.getTime() + ttl).toISOString(),
  };
}

/**
 * Checks that ownerAddress signed this exact challenge (EIP-191) while it was valid,
 * and that its nonce was not used before. No network calls. A nonce is recorded only
 * when verification succeeds, so a failed attempt cannot burn a valid challenge.
 */
export async function verifyChallenge(input: {
  challenge: Challenge;
  signature: string;
  ownerAddress: string;
  now: Date;
  nonces?: NonceStore;
}): Promise<VerifyResult> {
  const { challenge, signature, ownerAddress, now, nonces } = input;
  if (!isChallenge(challenge)) return { ok: false, reason: 'malformed_challenge' };
  if (!isSignature(signature)) return { ok: false, reason: 'malformed_signature' };
  if (!isAddress(ownerAddress)) return { ok: false, reason: 'malformed_owner' };
  const t = now.getTime();
  if (t < Date.parse(challenge.issuedAt)) return { ok: false, reason: 'not_yet_valid' };
  if (t >= Date.parse(challenge.expiresAt)) return { ok: false, reason: 'expired' };
  if (nonces?.has(challenge.nonce)) return { ok: false, reason: 'replayed_nonce' };
  let signer: string;
  try {
    signer = await recoverMessageAddress({ message: challengeMessage(challenge), signature });
  } catch {
    return { ok: false, reason: 'malformed_signature' };
  }
  if (signer.toLowerCase() !== ownerAddress.toLowerCase()) return { ok: false, reason: 'wrong_signer' };
  nonces?.add(challenge.nonce);
  return { ok: true, reason: 'ok' };
}

export function memoryNonceStore(): NonceStore {
  const seen = new Set<string>();
  return { has: (n) => seen.has(n), add: (n) => void seen.add(n) };
}

export { isNonce };
