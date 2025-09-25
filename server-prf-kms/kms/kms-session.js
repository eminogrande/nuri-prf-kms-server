/**
 * AWS KMS Session Manager
 * Handles GenerateMac operations against the configured HMAC key.
 */

import { KMSClient, GenerateMacCommand, DescribeKeyCommand } from "@aws-sdk/client-kms";
import crypto from "crypto";
import { asBuffer, secureWipe } from "./kms-utils.js";
import { recordAuditEntry } from "../audit-store.js";

const HMAC_ALGORITHM = "HMAC_SHA_256";

class KmsSessionManager {
  constructor() {
    const { AWS_REGION = "eu-north-1", KMS_KEY_ID } = process.env;

    this.region = AWS_REGION;
    this.kmsKeyId = KMS_KEY_ID;

    this.kmsClient = null;
    this.initialized = false;
    this.initializing = null;
    this.lastLogMac = null;
  }

  get isSimulation() {
    return false;
  }

  async init() {
    if (this.initialized) return;
    if (this.initializing) {
      await this.initializing;
      return;
    }

    this.initializing = (async () => {
      if (!this.kmsKeyId) {
        throw new Error("KMS_KEY_ID environment variable required for KMS operations");
      }

      this.kmsClient = new KMSClient({ region: this.region });

      if (typeof this.kmsClient.config.credentials === "function") {
        try {
          await this.kmsClient.config.credentials();
        } catch (error) {
          throw new Error(`AWS credentials not available: ${error.message}`);
        }
      }

      await this.verifyKmsKey();

      this.initialized = true;
      console.log("✅ AWS KMS session ready");
    })();

    try {
      await this.initializing;
    } finally {
      this.initializing = null;
    }
  }

  ensureReady() {
    if (!this.initialized) {
      throw new Error("KMS session not initialized. Call init() first.");
    }
  }

  async verifyKmsKey() {
    try {
      const response = await this.kmsClient.send(
        new DescribeKeyCommand({ KeyId: this.kmsKeyId })
      );

      if (!response.KeyMetadata?.Enabled) {
        throw new Error(`KMS key ${this.kmsKeyId} is not enabled`);
      }

      console.log(`✅ KMS key verified: ${response.KeyMetadata.Arn}`);
    } catch (error) {
      throw new Error(`Failed to verify KMS key: ${error.message}`);
    }
  }

  async signHmac(data) {
    this.ensureReady();
    const message = asBuffer(data);

    try {
      const { Mac } = await this.kmsClient.send(
        new GenerateMacCommand({
          KeyId: this.kmsKeyId,
          MacAlgorithm: HMAC_ALGORITHM,
          Message: message,
        })
      );

      if (!Mac) {
        throw new Error("KMS GenerateMac returned an empty response");
      }

      return Buffer.from(Mac);
    } finally {
      secureWipe(message);
    }
  }

  generateRandom(length) {
    if (length <= 0) {
      throw new Error("Random length must be positive");
    }

    return crypto.randomBytes(length);
  }

  async deriveEphemeralKey(tag = "nuri-session-key") {
    const nonce = this.generateRandom(32);
    const context = Buffer.concat([
      Buffer.from(tag, "utf8"),
      nonce,
      Buffer.from(Date.now().toString(16), "hex"),
    ]);

    const mac = await this.signHmac(context);
    const sessionKey = crypto.createHash("sha256").update(mac).digest();

    secureWipe(context);
    secureWipe(mac);

    return {
      key: sessionKey,
      nonce,
    };
  }

  async attestLog(event, payload = {}, { emit = true } = {}) {
    const timestamp = new Date().toISOString();
    const nonce = this.generateRandom(16);
    const serializedPayload = Buffer.from(
      JSON.stringify(payload ?? {}),
      "utf8"
    );

    const logMaterial = Buffer.concat([
      Buffer.from(timestamp, "utf8"),
      Buffer.from(event, "utf8"),
      serializedPayload,
      nonce,
      this.lastLogMac ?? Buffer.alloc(0),
    ]);

    const mac = await this.signHmac(logMaterial);
    const macBuffer = Buffer.from(mac);

    const entry = {
      timestamp,
      event,
      payload,
      nonce: nonce.toString("hex"),
      mac: macBuffer.toString("hex"),
      previousMac: this.lastLogMac ? this.lastLogMac.toString("hex") : null,
      kmsMode: true,
    };

    if (this.lastLogMac) {
      secureWipe(this.lastLogMac);
    }
    this.lastLogMac = macBuffer;

    recordAuditEntry(entry);

    if (emit) {
      console.log(JSON.stringify({ type: "kms.attestedLog", ...entry }));
    }

    secureWipe(serializedPayload);
    secureWipe(logMaterial);

    return entry;
  }

  async shutdown() {
    if (this.lastLogMac) {
      secureWipe(this.lastLogMac);
      this.lastLogMac = null;
    }
    this.kmsClient = null;
    this.initialized = false;
  }
}

const kmsSessionManager = new KmsSessionManager();
export default kmsSessionManager;
