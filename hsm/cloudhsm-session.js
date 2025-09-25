import crypto from "crypto";
import { asBuffer, secureWipe } from "./hsm-utils.js";

let graphenePromise = null;
async function loadGraphene() {
  if (!graphenePromise) {
    graphenePromise = import("graphene-pk11");
  }
  const mod = await graphenePromise;
  return mod?.default ?? mod;
}

class CloudHsmSessionManager {
  constructor() {
    const {
      HSM_PKCS11_LIB,
      HSM_USER_PIN,
      HSM_SLOT = "0",
      HSM_SIMULATION,
      HSM_MASTER_KEY_LABEL,
      NURI_MASTER_SECRET,
    } = process.env;

    this.libraryPath = HSM_PKCS11_LIB;
    this.userPin = HSM_USER_PIN;
    this.slotIndex = Number.parseInt(HSM_SLOT, 10);
    this.masterKeyLabel = HSM_MASTER_KEY_LABEL || "NURI_MASTER_SECRET";

    // Simulation mode has been removed - using real HSM only

    this.graphene = null;
    this.module = null;
    this.slot = null;
    this.session = null;
    this.masterKey = null;
    this.lastLogMac = null;
    this.initialized = false;
    this.initializing = null;
  }

  get isSimulation() {
    return false; // Always use real HSM
  }

  async init() {
    if (this.initialized) return;
    if (this.initializing) {
      await this.initializing;
      return;
    }

    // Real HSM mode only - no simulation

    if (!this.libraryPath || !this.userPin) {
      throw new Error(
        "CloudHSM configuration incomplete (HSM_PKCS11_LIB and HSM_USER_PIN required)",
      );
    }

    this.initializing = (async () => {
      this.graphene = await loadGraphene();
      this.module = this.graphene.Module.load(this.libraryPath, "CloudHSM");
      this.module.initialize();

      const slots = this.module.getSlots(true);
      if (!slots.length) {
        throw new Error("No CloudHSM slots available");
      }
      this.slot = slots[this.slotIndex] ?? slots[0];

      this.session = this.slot.open(
        this.graphene.SessionFlag.SERIAL_SESSION |
          this.graphene.SessionFlag.RW_SESSION,
      );

      this.session.login(this.userPin);
      this.masterKey = this.findSecretKey(this.masterKeyLabel);
      this.initialized = true;
    })();

    try {
      await this.initializing;
    } finally {
      this.initializing = null;
    }
  }

  async shutdown() {
    if (this.session) {
      try {
        this.session.logout();
      } catch {}
      try {
        this.session.close();
      } catch {}
    }
    if (this.module) {
      try {
        this.module.finalize();
      } catch {}
    }
    this.masterKey = null;
    this.session = null;
    this.slot = null;
    this.module = null;
    this.graphene = null;
    this.initialized = false;
  }

  ensureReady() {
    if (!this.initialized) {
      throw new Error("CloudHSM session not initialized. Call init() first.");
    }
  }

  findSecretKey(label) {
    const objects = this.session.find({
      class: this.graphene.ObjectClass.SECRET_KEY,
      label,
    });

    if (!objects.length) {
      throw new Error(`Secret key with label "${label}" not found in CloudHSM`);
    }
    return objects.items(0);
  }

  signHmac(data, { label = this.masterKeyLabel, keyHandle = null } = {}) {
    const message = asBuffer(data);

    // Real HSM signing only

    this.ensureReady();

    const handle =
      keyHandle ||
      (label === this.masterKeyLabel && this.masterKey) ||
      this.findSecretKey(label);

    const signer = this.session.createSign(
      handle,
      this.graphene.MechanismEnum.SHA256_HMAC,
    );
    signer.update(message);
    const mac = Buffer.from(signer.final());
    secureWipe(message);
    return mac;
  }

  generateRandom(length) {
    if (length <= 0) {
      throw new Error("Random length must be positive");
    }

    // Real HSM random generation only

    this.ensureReady();
    return Buffer.from(this.session.generateRandom(length));
  }

  deriveEphemeralKey(tag = "nuri-session-key") {
    const nonce = this.generateRandom(32);
    const context = Buffer.concat([
      Buffer.from(tag, "utf8"),
      nonce,
      Buffer.from(Date.now().toString(16), "hex"),
    ]);

    const mac = this.signHmac(context);
    const sessionKey = crypto.createHash("sha256").update(mac).digest();

    secureWipe(context);
    secureWipe(mac);

    return {
      key: sessionKey,
      nonce,
    };
  }

  attestLog(event, payload = {}, { emit = true } = {}) {
    const timestamp = new Date().toISOString();
    const nonce = this.generateRandom(16);
    const serializedPayload = Buffer.from(
      JSON.stringify(payload ?? {}),
      "utf8",
    );

    const logMaterial = Buffer.concat([
      Buffer.from(timestamp, "utf8"),
      Buffer.from(event, "utf8"),
      serializedPayload,
      nonce,
      this.lastLogMac ?? Buffer.alloc(0),
    ]);

    const mac = this.signHmac(logMaterial);

    const entry = {
      timestamp,
      event,
      payload,
      nonce: nonce.toString("hex"),
      mac: mac.toString("hex"),
      previousMac: this.lastLogMac ? this.lastLogMac.toString("hex") : null,
    };

    this.lastLogMac = mac;

    if (emit) {
      const record = {
        type: "cloudhsm.attestedLog",
        ...entry,
      };
      console.log(JSON.stringify(record));
    }

    secureWipe(serializedPayload);
    secureWipe(logMaterial);

    return entry;
  }
}

const cloudHsmSessionManager = new CloudHsmSessionManager();
export default cloudHsmSessionManager;
