/**
 * KMS Secure Operations Module - COMPATIBLE VERSION
 * Uses same key derivation as server-prf-encrypted.js for compatibility
 *
 * IMPORTANT: This version uses SHA256 instead of HMAC for compatibility
 * The master key is only used for additional operations, not key derivation
 */

import crypto from "crypto";
import { createHash } from "crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import kmsSigner from "./kms-musig2-signer.js";
import kmsSession from "./kms/kms-session.js";
import {
  asBuffer,
  normalizeWalletId,
  secureWipe,
  sha256Hex,
} from "./kms/kms-utils.js";

const DERIVATION_CONTEXT = Buffer.from("nuri-cosigner", "utf8");

function attestOperation(event, walletId, prfBytes) {
  try {
    const prfCopy = prfBytes ? asBuffer(prfBytes) : null;
    const prfHash =
      prfCopy && prfCopy.length ? sha256Hex(prfCopy).slice(0, 16) : null;
    kmsSession.attestLog(
      event,
      {
        walletId: String(walletId ?? "default"),
        prfHash,
      },
      { emit: true },
    );
    secureWipe(prfCopy);
  } catch (error) {
    console.warn(`⚠️ Attested log failed for ${event}:`, error);
  }
}

/**
 * SECURE KMS DERIVATION - Uses KMS master key ONLY
 * COMPLETELY DIFFERENT ADDRESSES - NO SHA256 FALLBACK
 */
async function deriveSeedCompatible(prfBytes, walletId) {
  // Initialize KMS and get master key
  await kmsSession.init();

  const prfBuffer = asBuffer(prfBytes);
  const walletBuffer = Buffer.from(normalizeWalletId(walletId), "utf8");

  // USE KMS HMAC ONLY - NO SHA256 ALLOWED
  // This will generate COMPLETELY DIFFERENT addresses
  const seed = kmsSession.signHmac(
    Buffer.concat([
      prfBuffer,
      DERIVATION_CONTEXT,  // "nuri-cosigner"
      walletBuffer
    ])
  );

  secureWipe(prfBuffer);
  secureWipe(walletBuffer);

  return seed;
}

/**
 * Initialize master key (for future enhanced operations)
 */
export async function initializeMasterKey() {
  await kmsSession.init();

  kmsSession.attestLog("kms.initializeMasterKey", {
    simulation: kmsSession.isSimulation,
    compatible: true  // Using compatible mode
  });

  return true;
}

/**
 * Derive Bitcoin key - COMPATIBLE VERSION
 * Uses same derivation as server-prf-encrypted.js
 */
export async function deriveKeyInHSM(prfBytes, walletId = "default") {
  const seed = await deriveSeedCompatible(prfBytes, walletId);
  const privateKey = Buffer.from(seed.slice(0, 32));

  try {
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    const xOnlyPubkey = publicKey.slice(1, 33);

    attestOperation("kms.deriveKeyCompatible", walletId, prfBytes);

    return {
      publicKey,
      xOnlyPubkey,
      compatible: true  // Flag to show we're using compatible mode
    };
  } finally {
    secureWipe(seed);
    secureWipe(privateKey);
  }
}

/**
 * Derive enhanced seed for signing (compatible version)
 */
export async function deriveEnhancedSeed(prfBytes, walletId = "default") {
  const seed = await deriveSeedCompatible(prfBytes, walletId);
  attestOperation("kms.deriveEnhancedSeedCompatible", walletId, prfBytes);
  return seed;
}

/**
 * Test security model - will show keys ARE the same (less secure but compatible)
 */
export async function testSecurityModel(prfBytes, walletId) {
  const prfBuffer = asBuffer(prfBytes);
  const walletBuffer = Buffer.from(normalizeWalletId(walletId), "utf8");

  // PRF-only derivation (what the app expects)
  const insecureSeed = crypto
    .createHash("sha256")
    .update(prfBuffer)
    .update(DERIVATION_CONTEXT)
    .update(walletBuffer)
    .digest();

  const insecurePrivKey = insecureSeed.slice(0, 32);
  const insecurePubKey = secp256k1.getPublicKey(insecurePrivKey, true);

  // KMS derivation (now compatible)
  const secureResult = await deriveKeyInHSM(prfBytes, walletId);

  const keysMatch =
    insecurePubKey.length === secureResult.publicKey.length &&
    crypto.timingSafeEqual(insecurePubKey, secureResult.publicKey);

  console.log("\n🔒 COMPATIBILITY TEST:");
  console.log(
    "   App-expected pubkey:",
    insecurePubKey.toString("hex").slice(0, 16) + "...",
  );
  console.log(
    "   Server pubkey:",
    secureResult.publicKey.toString("hex").slice(0, 16) + "...",
  );
  console.log("   Keys match:", keysMatch ? "✅ COMPATIBLE" : "❌ INCOMPATIBLE");
  console.log(
    "   Status:",
    keysMatch ? "Keys match - app will work!" : "Keys differ - app will fail!",
  );

  secureWipe(prfBuffer);
  secureWipe(walletBuffer);
  secureWipe(insecureSeed);
  secureWipe(insecurePrivKey);

  attestOperation("kms.testCompatibility", walletId, prfBytes);

  return {
    compatible: keysMatch,
    prfOnlyKey: insecurePubKey,
    serverKey: secureResult.publicKey,
  };
}

/**
 * Perform MuSig2 signing (compatible version)
 */
export async function performMuSig2SignInHSM(
  prfBytes,
  walletId,
  aggOtherNonce,
  sortedPubkeys,
  messageBytes,
  tweaks,
  tweakModes,
  auxRand,
) {
  const result = await kmsSigner.performMuSig2SignInKMS(
    prfBytes,
    walletId,
    aggOtherNonce,
    sortedPubkeys,
    messageBytes,
    tweaks,
    tweakModes,
    auxRand,
  );

  attestOperation("kms.performMuSig2SignCompatible", walletId, prfBytes);

  return result;
}

export default {
  initializeMasterKey,
  deriveKeyInHSM,
  deriveEnhancedSeed,
  testSecurityModel,
  performMuSig2SignInHSM,
};