#!/usr/bin/env node
/**
 * umami signing keys — generate, derive, rotate.
 *
 * umami signs ES256 with a private EC P-256 JWK carrying its own `kid`
 * (`UMAMI_SIGNING_KEY`), and publishes the public half at
 * `/.well-known/jwks.json`. Retired public keys stay in the JWKS via
 * `UMAMI_PREVIOUS_KEYS` so tokens signed just before a rotation still verify
 * until they expire.
 *
 * Deliberately free of any secret store: where the key ends up — Secrets
 * Manager, Vault, a sealed secret, an .env file — is the deployment's business.
 * This only does the cryptography, over stdin and stdout, so it composes:
 *
 *   node scripts/keys.mjs new --kid sandbox-1 > key.jwk
 *   node scripts/keys.mjs public < key.jwk
 *   node scripts/keys.mjs rotate --kid sandbox-2 --previous prev.json < key.jwk
 *
 * Node 18+; no dependencies.
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

const USAGE = `umami signing keys

  new     --kid <id>                       print a fresh private P-256 JWK
  public                                   read a private JWK on stdin, print its public half
  rotate  --kid <id> [--previous <file>]   read the *current* private JWK on stdin and print
                                           { signingKey, previousKeys } for the new generation

Options:
  --keep <n>   rotate: how many retired public keys to keep (default 2)

Rotation, end to end:
  1. rotate < current-key.jwk  →  the new private key plus the retired public keys
  2. store signingKey as UMAMI_SIGNING_KEY, previousKeys as UMAMI_PREVIOUS_KEYS
  3. restart umami
Both must land in the same restart: a running instance signs with the key it was
started with, and only the keys in its JWKS can be verified by anyone.
`;

/** A fresh private EC P-256 JWK. `alg`/`use` are informational; umami sets them in the JWKS too. */
function newKey(kid) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' });
  return { ...jwk, kid, alg: 'ES256', use: 'sig' };
}

/**
 * The public half: the same JWK without the private scalar `d`.
 *
 * Re-imported through WebCrypto first, so a malformed or non-P-256 input fails here rather
 * than silently producing a "public key" that verifies nothing.
 */
function publicHalf(jwk) {
  const key = createPublicKey({ key: { ...jwk, d: undefined }, format: 'jwk' });
  const exported = key.export({ format: 'jwk' });
  return { ...exported, kid: jwk.kid, alg: 'ES256', use: 'sig' };
}

function assertPrivateP256(jwk, source) {
  if (jwk?.kty !== 'EC' || jwk?.crv !== 'P-256') {
    throw new Error(`${source}: expected an EC P-256 JWK, got kty=${jwk?.kty} crv=${jwk?.crv}`);
  }
  if (!jwk.d) {
    throw new Error(`${source}: this is a public JWK (no "d"); the private key is required`);
  }
  if (!jwk.kid) {
    throw new Error(`${source}: the JWK needs a "kid" — umami refuses a signing key without one`);
  }
  // Proves the curve point and scalar actually form a usable key.
  createPrivateKey({ key: jwk, format: 'jwk' });
}

function readStdin() {
  const raw = readFileSync(0, 'utf-8').trim();
  if (!raw) {
    throw new Error('nothing on stdin — pipe the current private JWK in');
  }
  return JSON.parse(raw);
}

function flag(args, name) {
  const at = args.indexOf(name);
  return at === -1 ? undefined : args[at + 1];
}

function main() {
  const [command, ...args] = process.argv.slice(2);

  if (!command || command === '--help' || command === '-h') {
    process.stdout.write(USAGE);
    return;
  }

  if (command === 'new') {
    const kid = flag(args, '--kid');
    if (!kid) {
      throw new Error('new: --kid is required. Use something traceable, e.g. sandbox-2026-08-27.');
    }
    process.stdout.write(`${JSON.stringify(newKey(kid))}\n`);
    return;
  }

  if (command === 'public') {
    const jwk = readStdin();
    assertPrivateP256(jwk, 'stdin');
    process.stdout.write(`${JSON.stringify(publicHalf(jwk))}\n`);
    return;
  }

  if (command === 'rotate') {
    const kid = flag(args, '--kid');
    if (!kid) {
      throw new Error('rotate: --kid is required for the new key.');
    }
    const keep = Number(flag(args, '--keep') ?? 2);

    const current = readStdin();
    assertPrivateP256(current, 'stdin (the current key)');
    if (current.kid === kid) {
      throw new Error(
        `rotate: the new kid "${kid}" equals the current one. Two different keys sharing a kid ` +
          `makes the JWKS ambiguous — verifiers pick by kid.`,
      );
    }

    const previousFile = flag(args, '--previous');
    let previous = [];
    if (previousFile) {
      try {
        previous = JSON.parse(readFileSync(previousFile, 'utf-8').trim() || '[]');
      } catch (err) {
        throw new Error(`rotate: cannot read --previous ${previousFile}: ${err.message}`);
      }
      if (!Array.isArray(previous)) {
        throw new Error('rotate: --previous must contain a JSON array of public JWKs');
      }
    }

    // Newest retirement first, older ones dropped past --keep. Access tokens are short-lived
    // (security.accessTtlSecs, 10 minutes by default), so one retired key already covers any
    // in-flight token; keeping two is slack for a rotation that gets interrupted.
    const retired = publicHalf(current);
    const previousKeys = [retired, ...previous.filter((k) => k.kid !== retired.kid)].slice(0, keep);

    process.stdout.write(
      `${JSON.stringify({ signingKey: newKey(kid), previousKeys }, null, 2)}\n`,
    );
    return;
  }

  throw new Error(`unknown command "${command}"\n\n${USAGE}`);
}

try {
  main();
} catch (err) {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
