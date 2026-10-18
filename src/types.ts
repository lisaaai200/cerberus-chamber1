export interface Challenge {
  did: string;
  listingId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

export interface NonceStore {
  has(nonce: string): boolean;
  add(nonce: string): void;
}

export type VerifyReason =
  | 'ok'
  | 'malformed_challenge'
  | 'malformed_signature'
  | 'malformed_owner'
  | 'not_yet_valid'
  | 'expired'
  | 'replayed_nonce'
  | 'wrong_signer';

export interface VerifyResult {
  ok: boolean;
  reason: VerifyReason;
}
