/**
 * KMS MuSig2 Signer - Official @scure/btc-signer integration
 *
 * CRITICAL SECURITY PROPERTIES:
 * - Uses official @scure/btc-signer/musig2.js for 100% client compatibility
 * - Private keys derived via KMS, zeroized immediately after use
 * - Only public values (nonces, signatures) exit the signer
 */

import * as musig2 from "@scure/btc-signer/musig2.js";
import { deriveEnhancedSeed } from "./kms-secure-operations-compatible.js";
import { secureWipe } from "./kms/kms-utils.js";

/**
 * Perform MuSig2 deterministic signing using official scure library
 * Private key is derived via KMS and used only for signing, never exposed
 *
 * This uses the exact same @scure/btc-signer/musig2.js that the client uses
 */
export async function performMuSig2SignInKMS(
  prfBytes,
  walletId,
  aggOtherNonce,
  sortedPubkeys,
  messageBytes,
  tweaks,
  tweakModes,
  auxRand,
) {
  // Step 1: Derive key material using KMS (replaces direct seed derivation)
  const seedMaterial = await deriveEnhancedSeed(prfBytes, walletId);
  const privateKey = Buffer.from(seedMaterial.slice(0, 32));

  try {
    // Step 2: Use official @scure/btc-signer MuSig2 implementation
    // This ensures 100% compatibility with client-side signing
    const result = musig2.deterministicSign(
      privateKey,
      aggOtherNonce,
      sortedPubkeys,
      messageBytes,
      tweaks,
      tweakModes,
      auxRand,
      false, // fastSign = false for validation
    );

    return {
      publicNonce: result.publicNonce,
      partialSig: result.partialSig,
      publicKey: musig2.IndividualPubkey(privateKey), // For verification
    };
  } finally {
    // Clear sensitive data
    secureWipe(seedMaterial);
    secureWipe(privateKey);
  }
}

export default {
  performMuSig2SignInKMS,
};
