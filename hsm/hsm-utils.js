/**
 * Shared HSM helper utilities.
 *
 * These helpers are intentionally tiny so they can be imported from both the
 * CloudHSM session manager and any higher-level modules without creating
 * circular dependencies.
 */

import crypto from 'crypto';

/**
 * Convert arbitrary input into a Node.js Buffer.
 * Accepts Buffers, ArrayBuffers, TypedArrays, DataViews, and strings.
 *
 * @param {Buffer | ArrayBuffer | ArrayBufferView | string} data
 * @param {BufferEncoding} [encoding='utf8']
 * @returns {Buffer}
 */
export function asBuffer(data, encoding = 'utf8') {
  if (Buffer.isBuffer(data)) {
    return Buffer.from(data);
  }
  if (data instanceof ArrayBuffer) {
    return Buffer.from(data);
  }
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(
      data.buffer,
      data.byteOffset,
      data.byteLength
    );
  }
  if (typeof data === 'string') {
    return Buffer.from(data, encoding);
  }
  throw new TypeError('Unsupported data type for buffer conversion');
}

/**
 * Overwrite a buffer or typed array with zeros.
 * Intended for best-effort scrubbing of sensitive material.
 *
 * @param {Buffer | Uint8Array | undefined | null} target
 */
export function secureWipe(target) {
  if (!target) return;
  if (typeof target.fill === 'function') {
    target.fill(0);
  }
}

/**
 * Compute a SHA-256 hash of data and return the hex string.
 * Useful when emitting attested logs that should not expose raw payloads.
 *
 * @param {Buffer | ArrayBuffer | ArrayBufferView | string} data
 * @returns {string}
 */
export function sha256Hex(data) {
  return crypto.createHash('sha256').update(asBuffer(data)).digest('hex');
}

/**
 * Ensure a value is coerced to a string. Falls back to 'default' when nullish.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function normalizeWalletId(value) {
  if (value === undefined || value === null) {
    return 'default';
  }
  return String(value);
}
