import type { Challenge } from './types.js';

export const DEFAULT_TTL_MS = 5 * 60 * 1000;
export const MAX_TTL_MS = 60 * 60 * 1000;

const DID_RE = /^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/;
const NONCE_RE = /^[0-9a-f]{32,128}$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE_RE = /^0x[0-9a-fA-F]{130}$/;

export const isDid = (v: unknown): v is string => typeof v === 'string' && DID_RE.test(v);
export const isNonce = (v: unknown): v is string => typeof v === 'string' && NONCE_RE.test(v);
export const isAddress = (v: unknown): v is `0x${string}` => typeof v === 'string' && ADDRESS_RE.test(v);
export const isSignature = (v: unknown): v is `0x${string}` => typeof v === 'string' && SIGNATURE_RE.test(v);
export const isListingId = (v: unknown): v is string =>
  typeof v === 'string' && v.length > 0 && v.length <= 128 && !/[\r\n]/.test(v);

const isIso = (v: unknown): v is string =>
  typeof v === 'string' && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString() === v;

export function isChallenge(c: unknown): c is Challenge {
  if (c === null || typeof c !== 'object') return false;
  const x = c as Record<string, unknown>;
  if (!isDid(x.did) || !isListingId(x.listingId) || !isNonce(x.nonce)) return false;
  if (!isIso(x.issuedAt) || !isIso(x.expiresAt)) return false;
  const span = Date.parse(x.expiresAt) - Date.parse(x.issuedAt);
  return span > 0 && span <= MAX_TTL_MS;
}

/** The exact text the listing owner signs with EIP-191 personal_sign. */
export function challengeMessage(c: Challenge): string {
  return [
    'LAX identity challenge',
    `DID: ${c.did}`,
    `Listing: ${c.listingId}`,
    `Nonce: ${c.nonce}`,
    `Issued: ${c.issuedAt}`,
    `Expires: ${c.expiresAt}`,
  ].join('\n');
}
