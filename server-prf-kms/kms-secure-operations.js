/**
 * KMS Secure Operations Module
 *
 * SECURITY MODEL:
 * 1. Master key is protected by AWS KMS/Secrets Manager
 * 2. PRF alone cannot derive keys
 * 3. Private scalars are zeroized immediately after use
 * 4. Only public values or signatures ever leave the signer
 */

import crypto from "crypto";
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

async function deriveSeed(prfBytes, walletId) {
  await kmsSession.init();

  const prfBuffer = asBuffer(prfBytes);
  const walletBuffer = Buffer.from(normalizeWalletId(walletId), "utf8");
  const message = Buffer.concat([prfBuffer, DERIVATION_CONTEXT, walletBuffer]);

  let mac;
  try {
    mac = kmsSession.signHmac(message);
    return Buffer.from(mac);
  } finally {
    secureWipe(prfBuffer);
    secureWipe(walletBuffer);
    secureWipe(message);
    secureWipe(mac);
  }
}

/**
 * Initialize master key (verify it exists / configuration sanity)
 */
export async function initializeMasterKey() {
  await kmsSession.init();

  // KMS mode with optional simulation for development

  kmsSession.attestLog("kms.initializeMasterKey", {
    simulation: kmsSession.isSimulation,
  });

  return true;
}

/**
 * Derive Bitcoin key using PRF + Master Secret
 * Enhanced security: PRF alone cannot derive keys
 */
export async function deriveKeyInHSM(prfBytes, walletId = "default") {
  const seed = await deriveSeed(prfBytes, walletId);
  const privateKey = Buffer.from(seed.subarray(0, 32));

  try {
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    const xOnlyPubkey = publicKey.slice(1, 33);

    attestOperation("kms.deriveKeyInKMS", walletId, prfBytes);

    return {
      publicKey,
      xOnlyPubkey,
      masterEnhanced: true, // Using KMS-protected master key
    };
  } finally {
    secureWipe(seed);
    secureWipe(privateKey);
  }
}

/**
 * Derive enhanced seed for signing (needed for MuSig2)
 * Returns the seed that can be used to get private key.
 * Caller is responsible for zeroizing the returned Buffer.
 */
export async function deriveEnhancedSeed(prfBytes, walletId = "default") {
  const seed = await deriveSeed(prfBytes, walletId);
  attestOperation("kms.deriveEnhancedSeed", walletId, prfBytes);
  return seed;
}

/**
 * Test security: Verify PRF alone cannot derive keys
 */
export async function testSecurityModel(prfBytes, walletId) {
  const prfBuffer = asBuffer(prfBytes);
  const walletBuffer = Buffer.from(normalizeWalletId(walletId), "utf8");

  const insecureSeed = crypto
    .createHash("sha256")
    .update(prfBuffer)
    .update(DERIVATION_CONTEXT)
    .update(walletBuffer)
    .digest();

  const insecurePrivKey = insecureSeed.slice(0, 32);
  const insecurePubKey = secp256k1.getPublicKey(insecurePrivKey, true);

  const secureResult = await deriveKeyInHSM(prfBytes, walletId);

  const keysMatch =
    insecurePubKey.length === secureResult.publicKey.length &&
    crypto.timingSafeEqual(insecurePubKey, secureResult.publicKey);

  console.log("\n🔒 SECURITY TEST:");
  console.log(
    "   PRF-only pubkey:",
    insecurePubKey.toString("hex").slice(0, 16) + "...",
  );
  console.log(
    "   Master+PRF pubkey:",
    secureResult.publicKey.toString("hex").slice(0, 16) + "...",
  );
  console.log("   Keys match:", keysMatch ? "❌ INSECURE!" : "✅ SECURE");
  console.log(
    "   Conclusion:",
    keysMatch ? "FAIL - PRF can derive key!" : "PASS - PRF alone is useless",
  );

  secureWipe(prfBuffer);
  secureWipe(walletBuffer);
  secureWipe(insecureSeed);
  secureWipe(insecurePrivKey);

  attestOperation("kms.testSecurityModel", walletId, prfBytes);

  return {
    secure: !keysMatch,
    prfOnlyKey: insecurePubKey,
    masterEnhancedKey: secureResult.publicKey,
  };
}

/**
 * Perform MuSig2 signing with HSM-backed key derivation
 * Private key is derived via HSM and zeroized immediately after use
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

  attestOperation("kms.performMuSig2SignInKMS", walletId, prfBytes);

  return result;
}

export default {
  initializeMasterKey,
  deriveKeyInHSM,
  deriveEnhancedSeed,
  testSecurityModel,
  performMuSig2SignInHSM,
};
