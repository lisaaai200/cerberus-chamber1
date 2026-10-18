import { describe, expect, it } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { challengeMessage, createChallenge, memoryNonceStore, verifyChallenge } from '../src/index.js';
import { isChallenge } from '../src/rules.js';

const owner = privateKeyToAccount(generatePrivateKey());
const stranger = privateKeyToAccount(generatePrivateKey());
const now = new Date('2026-10-20T12:00:00.000Z');
const later = (ms: number) => new Date(now.getTime() + ms);
const base = { did: 'did:web:agent.example.com', listingId: 'listing-123', now };

async function signed(acct = owner, overrides = {}) {
  const challenge = createChallenge({ ...base, nonce: 'a'.repeat(32), ...overrides });
  const signature = await acct.signMessage({ message: challengeMessage(challenge) });
  return { challenge, signature };
}

describe('createChallenge', () => {
  it('builds a valid challenge with a random nonce and default ttl', () => {
    const c = createChallenge(base);
    expect(isChallenge(c)).toBe(true);
    expect(Date.parse(c.expiresAt) - Date.parse(c.issuedAt)).toBe(5 * 60 * 1000);
    expect(createChallenge(base).nonce).not.toBe(c.nonce);
  });
  it('rejects bad input', () => {
    expect(() => createChallenge({ ...base, did: 'nope' })).toThrow('invalid did');
    expect(() => createChallenge({ ...base, listingId: '' })).toThrow('invalid listing id');
    expect(() => createChallenge({ ...base, listingId: 'a\nb' })).toThrow('invalid listing id');
    expect(() => createChallenge({ ...base, ttlMs: 0 })).toThrow('invalid ttl');
    expect(() => createChallenge({ ...base, ttlMs: 2 * 60 * 60 * 1000 })).toThrow('invalid ttl');
    expect(() => createChallenge({ ...base, ttlMs: 1.5 })).toThrow('invalid ttl');
    expect(() => createChallenge({ ...base, nonce: 'xyz' })).toThrow('invalid nonce');
  });
});

describe('verifyChallenge', () => {
  it('accepts a valid signature from the listing owner (checksum-insensitive)', async () => {
    const { challenge, signature } = await signed();
    const r = await verifyChallenge({ challenge, signature, ownerAddress: owner.address.toLowerCase(), now: later(1000) });
    expect(r).toEqual({ ok: true, reason: 'ok' });
  });
  it('refuses a wrong signer', async () => {
    const { challenge, signature } = await signed(stranger);
    expect(await verifyChallenge({ challenge, signature, ownerAddress: owner.address, now })).toEqual({ ok: false, reason: 'wrong_signer' });
  });
  it('refuses an expired challenge, at and after expiry', async () => {
    const { challenge, signature } = await signed();
    expect((await verifyChallenge({ challenge, signature, ownerAddress: owner.address, now: later(5 * 60 * 1000) })).reason).toBe('expired');
    expect((await verifyChallenge({ challenge, signature, ownerAddress: owner.address, now: later(10 * 60 * 1000) })).reason).toBe('expired');
  });
  it('refuses a challenge used before it was issued', async () => {
    const { challenge, signature } = await signed();
    expect((await verifyChallenge({ challenge, signature, ownerAddress: owner.address, now: later(-1) })).reason).toBe('not_yet_valid');
  });
  it('refuses a replayed nonce, and does not burn a nonce on failure', async () => {
    const nonces = memoryNonceStore();
    const { challenge, signature } = await signed();
    const bad = await signed(stranger);
    expect((await verifyChallenge({ ...bad, ownerAddress: owner.address, now, nonces })).reason).toBe('wrong_signer');
    expect((await verifyChallenge({ challenge, signature, ownerAddress: owner.address, now, nonces })).ok).toBe(true);
    expect((await verifyChallenge({ challenge, signature, ownerAddress: owner.address, now, nonces })).reason).toBe('replayed_nonce');
  });
  it('refuses a tampered DID or listing id', async () => {
    const { challenge, signature } = await signed();
    const r1 = await verifyChallenge({ challenge: { ...challenge, did: 'did:web:evil.example.com' }, signature, ownerAddress: owner.address, now });
    const r2 = await verifyChallenge({ challenge: { ...challenge, listingId: 'listing-999' }, signature, ownerAddress: owner.address, now });
    expect(r1.reason).toBe('wrong_signer');
    expect(r2.reason).toBe('wrong_signer');
  });
  it('refuses malformed input', async () => {
    const { challenge, signature } = await signed();
    const v = (o: object) => verifyChallenge({ challenge, signature, ownerAddress: owner.address, now, ...o } as never);
    expect((await v({ challenge: null })).reason).toBe('malformed_challenge');
    expect((await v({ challenge: 'x' })).reason).toBe('malformed_challenge');
    expect((await v({ challenge: { ...challenge, did: 'x' } })).reason).toBe('malformed_challenge');
    expect((await v({ challenge: { ...challenge, issuedAt: 'yesterday' } })).reason).toBe('malformed_challenge');
    expect((await v({ challenge: { ...challenge, expiresAt: challenge.issuedAt } })).reason).toBe('malformed_challenge');
    expect((await v({ challenge: { ...challenge, nonce: 'zz' } })).reason).toBe('malformed_challenge');
    expect((await v({ challenge: { ...challenge, listingId: 5 } })).reason).toBe('malformed_challenge');
    expect((await v({ signature: '0x1234' })).reason).toBe('malformed_signature');
    expect((await v({ signature: '0x' + '00'.repeat(65) })).reason).toBe('malformed_signature');
    expect((await v({ ownerAddress: 'owner' })).reason).toBe('malformed_owner');
  });
});
