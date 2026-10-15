/**
 * foc-encryption — COSE-based encryption envelopes for content-addressed data.
 *
 * Provides AES-256-GCM encryption with COSE_Encrypt0/COSE_Encrypt envelopes,
 * optional chunked STREAM construction for seekable decryption, multi-recipient
 * key management descriptors, and keyless envelope inspection.
 *
 * @packageDocumentation
 */
/** Encrypt plaintext into a COSE envelope + ciphertext blob. */
export { decrypt, decryptRange, encrypt, parseEnvelope } from './envelope.js';
/** COSE algorithm identifiers and header parameter labels. */
export { CoseAlgorithm, CoseHeaderParam } from './cose/headers.js';
export { deriveKey } from './kdf.js';
export { 
/** AEAD authentication failed — tampered ciphertext or wrong key. */
AuthenticationError, 
/** Base error class for all library errors. */
FocEncryptionError, 
/** CEK is invalid (wrong size, all zeros). */
InvalidKeyError, 
/** COSE envelope is malformed or cannot be parsed. */
MalformedEnvelopeError, 
/** Range decryption requested on a non-seekable scheme. */
SchemeNotSeekableError, 
/** Encryption scheme is not recognized or not supported. */
UnsupportedSchemeError, } from './errors.js';
//# sourceMappingURL=index.js.map