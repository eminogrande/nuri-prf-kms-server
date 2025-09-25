// PRF Server with AWS KMS integration
// Uses AWS KMS/Secrets Manager for master key protection

import express from "express";
import cors from "cors";
import { createHash, createHmac } from "crypto";
import {
  bytesToHex,
  randomBytes as nobleRandomBytes,
} from "@noble/hashes/utils.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import base64url from "base64url";
import * as musig2 from "@scure/btc-signer/musig2.js";
import * as btc from "@scure/btc-signer";
import { hexToBytes } from "@noble/hashes/utils.js";
import { concatBytes } from "@noble/curves/utils.js";
import { v4 as uuidv4 } from "uuid";
import kmsOps from "./kms-secure-operations-compatible.js";
import kmsSession from "./kms/kms-session.js";
import { secureWipe } from "./kms/kms-utils.js";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessions = new Map();

// Counter for nonce generation (persists across requests, resets on restart)
let nonceCounter = BigInt(Date.now());

// Helper functions from example server
const HEX = /^[0-9a-fA-F]+$/;

// Helper to pick query parameters with fallbacks
function pick(q, ...names) {
  for (const n of names)
    if (q[n] != null && String(q[n]).length) return String(q[n]);
  return null;
}

// Validates if hex is 33-byte compressed key
function isCompressed33(h) {
  return (
    typeof h === "string" &&
    h.length === 66 &&
    HEX.test(h) &&
    (h.startsWith("02") || h.startsWith("03"))
  );
}

// Helper to convert public key to x-only hex (always 64 chars)
function toXOnlyHex(pubkey) {
  if (!pubkey || pubkey.length === 0) return "0".repeat(64);
  const bytes = pubkey.length === 33 ? pubkey.slice(1) : pubkey;
  return bytesToHex(bytes).padStart(64, "0");
}

// Encryption function - EXACTLY as the app expects
function encryptData(data, recipientPublicKey) {
  try {
    // Generate ephemeral X25519 keypair
    const ephemeralPrivateKey = x25519.utils.randomSecretKey();
    const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

    // Perform X25519 ECDH
    const sharedSecret = x25519.getSharedSecret(
      ephemeralPrivateKey,
      recipientPublicKey,
    );

    // HKDF exactly as app expects:
    // 1. Salt = SHA256("nuri-sealed-box-v1")
    const salt = sha256(new TextEncoder().encode("nuri-sealed-box-v1"));

    // 2. Info = "cosigner"
    const info = new TextEncoder().encode("cosigner");

    // 3. Derive 32-byte key using HKDF-SHA256
    const key = hkdf(sha256, sharedSecret, salt, info, 32);

    // Generate 24-byte nonce for XChaCha20-Poly1305
    const nonce = nobleRandomBytes(24);

    // Encrypt using XChaCha20-Poly1305
    const plaintext = new TextEncoder().encode(JSON.stringify(data));
    const cipher = xchacha20poly1305(key, nonce);
    const ciphertext = cipher.encrypt(plaintext);

    // Construct sealed box: ephemeral_pubkey || nonce || ciphertext
    const sealed = new Uint8Array(32 + 24 + ciphertext.length);
    sealed.set(ephemeralPublicKey, 0);
    sealed.set(nonce, 32);
    sealed.set(ciphertext, 56);

    // Encode as base64url (no padding)
    return base64url.encode(Buffer.from(sealed));
  } catch (error) {
    console.error("Encryption error:", error);
    return null;
  }
}

// GET /setup - WebAuthn PRF page
app.get("/setup", (req, res) => {
  const { wallet_id, pk_app, return_url, state } = req.query;

  // Store session
  sessions.set(wallet_id, {
    pk_app,
    return_url,
    state,
    timestamp: Date.now(),
  });

  const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Setup Wallet</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: system-ui;
            padding: 20px;
            max-width: 600px;
            margin: 0 auto;
        }
        button {
            font-size: 18px;
            padding: 15px 30px;
            cursor: pointer;
            margin: 10px 0;
            width: 100%;
            border-radius: 8px;
            background: #007bff;
            color: white;
            border: none;
        }
        #status {
            margin: 20px 0;
            padding: 15px;
            border-radius: 8px;
            background: #f8f9fa;
        }
        .error { background: #f8d7da; color: #721c24; }
        .success { background: #d4edda; color: #155724; }
    </style>
</head>
<body>
    <h2>Setup Wallet with Passkey</h2>

    <button onclick="createAndUsePasskey()">Create New Passkey</button>
    <button onclick="useExistingPasskey()">Use Existing Passkey</button>

    <div id="status"></div>

    <script>
    function generateRandomBytes(length) {
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        return array;
    }

    function bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    async function createAndUsePasskey() {
        const status = document.getElementById('status');
        status.className = '';
        status.textContent = 'Creating new passkey...';

        try {
            const userId = generateRandomBytes(32);
            const prfSalt = new TextEncoder().encode('nuri-wallet-${wallet_id}');

            // Create passkey with PRF
            const credential = await navigator.credentials.create({
                publicKey: {
                    challenge: generateRandomBytes(32),
                    rp: {
                        name: "Nuri Wallet",
                        id: window.location.hostname
                    },
                    user: {
                        id: userId,
                        name: 'wallet-${wallet_id}',
                        displayName: "Wallet User"
                    },
                    pubKeyCredParams: [
                        { alg: -7, type: "public-key" }
                    ],
                    authenticatorSelection: {
                        userVerification: "preferred",
                        residentKey: "preferred"
                    },
                    attestation: "none",
                    extensions: {
                        prf: {
                            eval: {
                                first: prfSalt
                            }
                        }
                    }
                }
            });

            const extensions = credential.getClientExtensionResults();
            if (extensions.prf && extensions.prf.enabled) {
                status.textContent = 'Passkey created! Authenticating...';
                setTimeout(() => useExistingPasskey(), 1000);
            } else {
                throw new Error('PRF not supported');
            }
        } catch (error) {
            status.className = 'error';
            status.textContent = 'Error: ' + error.message;
        }
    }

    async function useExistingPasskey() {
        const status = document.getElementById('status');
        status.className = '';
        status.textContent = 'Authenticating...';

        try {
            const prfSalt = new TextEncoder().encode('nuri-wallet-${wallet_id}');

            // Get PRF from passkey
            const assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: generateRandomBytes(32),
                    rpId: window.location.hostname,
                    userVerification: "preferred",
                    extensions: {
                        prf: {
                            eval: {
                                first: prfSalt
                            }
                        }
                    }
                }
            });

            const extensions = assertion.getClientExtensionResults();
            if (!extensions.prf || !extensions.prf.results || !extensions.prf.results.first) {
                throw new Error('PRF not available');
            }

            status.textContent = 'Deriving key...';

            // Send PRF to server
            const response = await fetch('/setup-complete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    wallet_id: '${wallet_id}',
                    prf: btoa(String.fromCharCode(...new Uint8Array(extensions.prf.results.first)))
                        .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, ''),
                    state: '${state}',
                    pk_app: '${pk_app}',
                    return_url: '${return_url}'
                })
            });

            if (!response.ok) {
                throw new Error('Server error');
            }

            const result = await response.json();

            status.className = 'success';
            status.textContent = 'Success! Redirecting...';

            // Redirect with encrypted data
            setTimeout(() => {
                window.location.href = result.redirect_url;
            }, 1000);

        } catch (error) {
            status.className = 'error';
            status.textContent = 'Error: ' + error.message;
        }
    }
    </script>
</body>
</html>`;

  res.type("html").send(html);
});

// POST /setup-complete - Process PRF and return ENCRYPTED response
app.post("/setup-complete", async (req, res) => {
  console.log("POST /setup-complete", req.body);

  const { wallet_id, prf, state, pk_app, return_url } = req.body;

  const session = sessions.get(wallet_id);
  console.log("Session:", session);

  // Use pk_app from body or session
  const appPublicKey = pk_app || session?.pk_app;
  const returnUrl = return_url || session?.return_url;

  if (!appPublicKey) {
    console.error("Missing app public key");
    return res.status(400).json({ error: "Missing app public key" });
  }

  try {
    // Convert PRF to bytes
    const prfBytes = base64url.toBuffer(prf);

    // Use HSM for key derivation with master key
    console.log(`🔐 Using HSM for key derivation (wallet: ${wallet_id})`);

    // Derive key IN HSM - private key never exposed
    const hsmResult = await kmsOps.deriveKeyInHSM(prfBytes, wallet_id);

    // Use HSM-derived public key
    const publicKey = hsmResult.publicKey;
    const pubkeyHex = bytesToHex(publicKey);
    const pubkeyXOnly = bytesToHex(hsmResult.xOnlyPubkey);

    console.log(`✅ Derived key in HSM for wallet ${wallet_id}`);

    // Create response payload
    const payload = {
      pubkey: pubkeyXOnly, // 64 hex (x-only)
      pubkey_compressed: pubkeyHex, // 66 hex (compressed)
      exp: Date.now() + 3600000, // 1 hour expiry
    };

    // Decode app's public key
    const appPubKeyBytes = base64url.toBuffer(appPublicKey);

    // Encrypt the payload
    const encryptedData = encryptData(payload, appPubKeyBytes);

    if (!encryptedData) {
      throw new Error("Encryption failed");
    }

    // Build redirect URL with encrypted data
    const redirectUrl = returnUrl || "nuri://cosigner-setup";
    const separator = redirectUrl.includes("?") ? "&" : "?";
    const finalUrl = `${redirectUrl}${separator}state=${state}&data=${encryptedData}`;

    res.json({
      redirect_url: finalUrl,
      success: true,
    });
  } catch (error) {
    console.error("Full error:", error);
    res.status(500).json({
      error: "Processing failed",
      message: error.message,
      details: error.stack,
    });
  }
});

// GET /sign - Main signing endpoint using proper MuSig2 (matches example server API)
app.get("/sign", async (req, res) => {
  // Generate request_id for this signing session
  const request_id = uuidv4().slice(0, 8);
  console.log(
    "\n🔵 ==================== NEW /sign REQUEST ====================",
  );
  console.log("📝 Request ID:", request_id);
  console.log("⏰ Timestamp:", new Date().toISOString());

  try {
    // Parse with fallbacks (accept legacy and camelCase)
    const client_pk33 = pick(
      req.query,
      "client_pk33",
      "clientPK33",
      "a_compressed",
      "aCompressed",
    );
    const server_pk33 = pick(
      req.query,
      "server_pk33",
      "serverPK33",
      "s_compressed",
      "sCompressed",
    );
    const client_pub_nonce = pick(
      req.query,
      "client_pub_nonce",
      "clientPubNonce66",
      "client_nonce",
    );
    const msg32 = pick(req.query, "msg32", "message32");
    const tweak32 = pick(req.query, "tweak32", "tapTweak");
    const psbt_b64 = pick(req.query, "psbt_b64", "psbt");
    const input_index_str = pick(req.query, "input_index", "inputIndex");

    // Other params (less critical)
    const wallet_id = req.query.wallet_id;
    const pk_app = req.query.pk_app;
    const return_url = req.query.return_url;
    const state = req.query.state;
    const amount = req.query.amount;
    const to_address = req.query.to_address;

    // Step 1: Log what we actually received
    console.log("\n📥 [STEP 1] Received Parameters:");
    console.log("[/sign] received", {
      client_pk33_len: client_pk33?.length ?? null,
      server_pk33_len: server_pk33?.length ?? null,
      client_pub_nonce_len: client_pub_nonce?.length ?? null,
      msg32_len: msg32?.length ?? null,
      tweak32_len: tweak32?.length ?? null,
      psbt_b64_len: psbt_b64?.length ?? null,
    });

    const html = `<!DOCTYPE html>
<html>
<head>
    <title>Sign Transaction</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: system-ui, -apple-system, sans-serif;
            padding: 20px;
            max-width: 600px;
            margin: 0 auto;
            background: #f5f5f5;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        h2 {
            margin-top: 0;
            color: #333;
        }
        .transaction-details {
            background: #f9f9f9;
            border-radius: 8px;
            padding: 16px;
            margin: 20px 0;
            text-align: left;
        }
        .detail-row {
            display: flex;
            margin: 12px 0;
            align-items: flex-start;
        }
        .detail-label {
            font-weight: 600;
            color: #666;
            min-width: 120px;
        }
        .detail-value {
            color: #333;
            word-break: break-all;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 14px;
        }
        button {
            font-size: 18px;
            padding: 15px 30px;
            cursor: pointer;
            margin: 20px 0;
            width: 100%;
            border-radius: 8px;
            background: #007bff;
            color: white;
            border: none;
            font-weight: 600;
        }
        button:hover {
            background: #0056b3;
        }
        #status {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            background: #f8f9fa;
        }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Sign Transaction</h2>

        ${
          !msg32 || !client_pk33 || !client_pub_nonce
            ? `
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="margin: 0 0 10px 0;">⚠️ Missing Required Parameters!</h3>
            <p>The app did not send the required MuSig2 signing parameters:</p>
            <ul style="text-align: left;">
                <li><strong>msg32:</strong> ${msg32 ? "✅ Provided" : "❌ MISSING"}</li>
                <li><strong>client_pk33:</strong> ${client_pk33 ? "✅ Provided" : "❌ MISSING"}</li>
                <li><strong>client_pub_nonce:</strong> ${client_pub_nonce ? "✅ Provided" : "❌ MISSING"}</li>
            </ul>
            <p style="margin: 10px 0 0 0;"><strong>Cannot create signature without these parameters!</strong></p>
            <p style="margin: 5px 0 0 0; font-size: 14px;">The app needs to send these parameters when calling /sign</p>
        </div>`
            : ""
        }

        <div class="transaction-details">
            <h3>Transaction Details</h3>
            <div class="detail-row">
                <span class="detail-label">Wallet ID:</span>
                <span class="detail-value">${wallet_id || "Unknown"}</span>
            </div>
            ${
              msg32
                ? `
            <div class="detail-row">
                <span class="detail-label">Message:</span>
                <span class="detail-value">${msg32}</span>
            </div>`
                : ""
            }
            ${
              client_pk33
                ? `
            <div class="detail-row">
                <span class="detail-label">Client Key:</span>
                <span class="detail-value">${client_pk33.substring(0, 20)}...</span>
            </div>`
                : ""
            }
            ${
              client_pub_nonce
                ? `
            <div class="detail-row">
                <span class="detail-label">Nonces:</span>
                <span class="detail-value">${client_pub_nonce.substring(0, 20)}...</span>
            </div>`
                : ""
            }
            ${
              state
                ? `
            <div class="detail-row">
                <span class="detail-label">State:</span>
                <span class="detail-value">${state}</span>
            </div>`
                : ""
            }
        </div>

        <button onclick="signWithPasskey()">Sign with Passkey</button>

        <div id="status"></div>
    </div>

    <script>
        async function signWithPasskey() {
            const status = document.getElementById('status');
            status.className = '';
            status.textContent = 'Authenticating with passkey...';

            try {
                const prfSalt = new TextEncoder().encode('nuri-wallet-${wallet_id}');

                // Trigger passkey authentication with PRF
                const assertion = await navigator.credentials.get({
                    publicKey: {
                        challenge: crypto.getRandomValues(new Uint8Array(32)),
                        rpId: window.location.hostname,
                        userVerification: "preferred",
                        extensions: {
                            prf: {
                                eval: {
                                    first: prfSalt
                                }
                            }
                        }
                    }
                });

                const extensions = assertion.getClientExtensionResults();
                if (!extensions.prf || !extensions.prf.results || !extensions.prf.results.first) {
                    throw new Error('PRF not available');
                }

                status.textContent = 'Authentication successful! PRF obtained.';
                status.className = 'success';

                // Hide the button after success
                document.querySelector('button').style.display = 'none';

                // For now, just log the PRF (next iteration will use it for signing)
                console.log('PRF obtained:', extensions.prf.results.first);

                // Convert PRF to base64url
                const prfBase64 = btoa(String.fromCharCode(...new Uint8Array(extensions.prf.results.first)))
                    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');

                status.textContent = 'Signing transaction...';

                // Send PRF to server to sign
                const response = await fetch('/sign-with-prf', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        wallet_id: '${wallet_id || ""}',
                        prf: prfBase64,
                        msg32: '${msg32 || ""}',
                        client_pk33: '${client_pk33 || ""}',
                        client_pub_nonce: '${client_pub_nonce || ""}',
                        tweak32: '${tweak32 || ""}',
                        psbt_b64: '${psbt_b64 || ""}',
                        pk_app: '${pk_app || ""}',
                        state: '${state || ""}',
                        return_url: '${return_url || ""}'
                    })
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    console.error('Server error:', errorData);
                    status.textContent = 'Error: ' + (errorData.error || response.statusText);
                    status.className = 'error';

                    // Display detailed error info
                    if (errorData.error === 'Missing required parameters for signing') {
                        status.innerHTML = '<strong>Cannot sign!</strong><br>Missing: ' +
                            (errorData.required || []).join(', ') + '<br>' +
                            '<small>App needs to send these parameters</small>';
                    }
                    return;
                }

                const result = await response.json();

                if (result.redirect_url) {
                    status.textContent = 'Transaction signed! Redirecting...';
                    // Redirect with signature
                    setTimeout(() => {
                        window.location.href = result.redirect_url;
                    }, 1000);
                } else if (result.server_pubkey) {
                    status.textContent = 'Public key retrieved: ' + result.server_pubkey;
                    // For pubkey-only requests, stay on page to show the result
                } else {
                    status.textContent = 'Response: ' + JSON.stringify(result);
                }

            } catch (error) {
                status.textContent = 'Authentication failed: ' + error.message;
                status.className = 'error';
            }
        }
    </script>
</body>
</html>`;
    res.type("html").send(html);
  } catch (error) {
    console.error("Error in /sign:", error);
    res.status(500).json({ error: "Server error", message: error.message });
  }
});

// POST /sign-with-prf - Actual signing endpoint
app.post("/sign-with-prf", async (req, res) => {
  console.log("POST /sign-with-prf", req.body);

  const {
    wallet_id,
    prf,
    msg32,
    client_pk33,
    client_pub_nonce,
    state,
    return_url,
    tweak32,
    pk_app,
    psbt_b64,
  } = req.body;

  if (!prf || !wallet_id) {
    return res.status(400).json({ error: "Missing required parameters" });
  }

  try {
    // Convert PRF to bytes
    const prfBytes = base64url.toBuffer(prf);

    // Get public key from KMS - private key protected by KMS
    const kmsKey = await kmsOps.deriveKeyInHSM(prfBytes, wallet_id);
    const publicKey = kmsKey.publicKey;
    const pubkeyHex = bytesToHex(publicKey);

    console.log(`✅ Derived key for signing wallet ${wallet_id} (KMS secured)`);
    console.log(`   Public key: ${pubkeyHex.slice(0, 16)}...`);
    console.log(`   Private key: NEVER EXPOSED (secured by KMS)`)
    console.log(`   Using master-key-enhanced derivation`);

    // ALL parameters are required for signing
    if (!msg32 || !client_pk33 || !client_pub_nonce) {
      return res.status(400).json({
        error: "Missing required parameters for signing",
        required: ["msg32", "client_pk33", "client_pub_nonce"],
        received: {
          msg32: msg32 || "empty",
          client_pk33: client_pk33 || "empty",
          client_pub_nonce: client_pub_nonce || "empty",
        },
      });
    }

    // Parse and validate inputs
    const messageBytes = Buffer.from(msg32, "hex");
    const clientPubkey = Buffer.from(client_pk33, "hex");
    const clientNonces = Buffer.from(client_pub_nonce, "hex");

    // Validate sizes
    if (messageBytes.length !== 32) {
      return res.status(400).json({
        error: "Invalid message",
        details: `Message must be 32 bytes (64 hex chars), got ${messageBytes.length} bytes`,
      });
    }

    if (clientPubkey.length !== 33) {
      return res.status(400).json({
        error: "Invalid client public key",
        details: `Client public key must be 33 bytes compressed (66 hex chars), got ${clientPubkey.length} bytes`,
      });
    }

    if (clientNonces.length !== 66) {
      return res.status(400).json({
        error: "Invalid client nonces",
        details: `Client nonces must be 66 bytes (132 hex chars), got ${clientNonces.length} bytes`,
      });
    }

    // Prepare tweaks if provided (for Taproot)
    let tweaks = [];
    let tweakModes = [];
    if (tweak32) {
      const tweakBytes = Buffer.from(tweak32, "hex");
      if (tweakBytes.length !== 32) {
        return res.status(400).json({
          error: "Invalid tweak",
          details: `Tweak must be 32 bytes (64 hex chars), got ${tweakBytes.length} bytes`,
        });
      }
      tweaks = [tweakBytes];
      tweakModes = [true]; // X-only mode for BIP341 Taproot
      console.log(`   Using Taproot tweak: ${tweak32.slice(0, 16)}...`);
    }

    // Create unique auxiliary randomness (prevents nonce reuse)
    const nonceCounter = Date.now();
    const auxRand = createHash("sha256")
      .update(Buffer.from(nonceCounter.toString()))
      .update(messageBytes)
      .update(clientPubkey)
      .digest();

    // Create partial signature using HSM - private key NEVER exposed
    const sortedKeys = musig2.sortKeys([publicKey, clientPubkey]);

    // Perform signing entirely via KMS
    const det = await kmsOps.performMuSig2SignInHSM(
      prfBytes,
      wallet_id,
      clientNonces,
      sortedKeys,
      messageBytes,
      tweaks, // Include tweak if provided
      tweakModes, // Use scalar mode for Taproot
      auxRand, // Unique auxiliary randomness
    );

    const signature = bytesToHex(det.partialSig);
    const serverNonce = bytesToHex(det.publicNonce);

    console.log(`✅ Created partial signature`);
    console.log(`   Partial sig: ${signature.slice(0, 20)}...`);
    console.log(`   Server nonce: ${serverNonce.slice(0, 20)}...`);

    // Prepare response data
    const responseData = {
      server_partial32: signature,
      server_pub_nonce66: serverNonce,
      request_id: wallet_id,
      exp: Date.now() + 60000, // 1 minute expiration
      tweaked: !!tweak32, // Indicate if tweak was applied
    };

    // If pk_app provided, encrypt response and return deep link
    if (pk_app) {
      try {
        const appPubKeyBytes = base64url.toBuffer(pk_app);
        const encryptedData = encryptData(responseData, appPubKeyBytes);

        if (!encryptedData) {
          throw new Error("Encryption failed");
        }

        // Build redirect URL with encrypted data (matches example server)
        const redirectUrl = return_url || "nuri://signature";
        const separator = redirectUrl.includes("?") ? "&" : "?";
        const finalUrl = `${redirectUrl}${separator}state=${state || ""}&data=${encryptedData}`;

        res.json({
          redirect_url: finalUrl,
          success: true,
        });
      } catch (encryptError) {
        console.error("Encryption error:", encryptError);
        return res.status(500).json({
          error: "Failed to encrypt response",
          details: encryptError.message,
        });
      }
    } else {
      // No encryption, return plain JSON
      res.json(responseData);
    }
  } catch (error) {
    console.error("Signing error:", error);
    res.status(500).json({
      error: "Signing failed",
      message: error.message,
    });
  }
});

// Export for Vercel
export default app;

// Only start server if not in Vercel
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 1337; // Using standard port for ngrok

  // Initialize KMS before starting server
  async function startServer() {
    try {
      // Initialize KMS master key
      await kmsOps.initializeMasterKey();

      // Test security model
      console.log("\n🔒 Testing KMS security model...");
      const testPRF = Buffer.from("test-prf-value");
      const securityTest = await kmsOps.testSecurityModel(
        testPRF,
        "test-wallet",
      );

      // We WANT incompatible keys! That means we're using KMS-only derivation
      // and generating completely different addresses
      if (securityTest.compatible) {
        console.error(
          "❌ SECURITY FAILURE: Still using old SHA256 derivation!",
        );
        process.exit(1);
      }

      if (securityTest.compatible) {
        console.log("⚠️ Running in COMPATIBLE mode: Using SHA256 derivation for app compatibility");
        console.log("   Note: This matches server-prf-encrypted.js behavior\n");
      } else {
        console.log("✅ Security test passed: PRF alone cannot derive keys\n");
      }

      // Start server
      kmsSession.attestLog("server.start", {
        port: PORT,
        environment: process.env.NODE_ENV || "development",
        kmsMode: !kmsSession.isSimulation,
      });

      let shuttingDown = false;
      const shutdown = async (signal) => {
        if (shuttingDown) return;
        shuttingDown = true;
        console.log(`\nReceived ${signal}. Shutting down gracefully...`);
        try {
          await kmsSession.shutdown();
        } catch (shutdownError) {
          console.error("Error during KMS shutdown:", shutdownError);
        } finally {
          process.exit(0);
        }
      };

      process.on("SIGINT", () => shutdown("SIGINT"));
      process.on("SIGTERM", () => shutdown("SIGTERM"));

      app.listen(PORT, "0.0.0.0", () => {
        console.log(`
🚀 KMS-Secured PRF Server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 Private keys: Secured by AWS KMS
📍 http://localhost:${PORT}
🔧 Mode: ${kmsSession.isSimulation ? 'Local Simulation' : 'AWS KMS'}

Features:
✅ WebAuthn PRF for key derivation
✅ AWS KMS/Secrets Manager integration
✅ Proper sealed box encryption
✅ Compatible with the app

Test locally:
  http://localhost:${PORT}/setup?wallet_id=test123&state=abc&pk_app=<base64url_pubkey>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        `);
      });
    } catch (error) {
      console.error("Failed to start KMS server:", error);
      process.exit(1);
    }
  }

  // Start the server with KMS initialization
  startServer();
}
