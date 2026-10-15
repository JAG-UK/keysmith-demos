import type { DecryptMetadata, EncStructureContext, EncryptResult, EncryptionScheme } from './scheme.js';
declare const BASE_NONCE_LENGTH = 7;
declare const AES_GCM_TAG_LENGTH = 16;
declare const DEFAULT_CHUNK_SIZE = 262144;
declare const MAX_CHUNK_INDEX = 4294967295;
export interface ChunkedEncryptParams {
    chunkSize?: number;
}
export declare class ChunkedAes256GcmStream implements EncryptionScheme {
    readonly name = "Chunked-AES-256-GCM-STREAM";
    readonly algorithmId = -65793;
    readonly isSeekable = true;
    private chunkSize;
    constructor(params?: ChunkedEncryptParams);
    encrypt(key: CryptoKey, plaintext: Uint8Array, protectedHeaders: Uint8Array, context: EncStructureContext): Promise<EncryptResult>;
    decrypt(key: CryptoKey, ciphertext: Uint8Array, iv: Uint8Array, protectedHeaders: Uint8Array, context: EncStructureContext, metadata?: DecryptMetadata): Promise<Uint8Array>;
    decryptRange(key: CryptoKey, ciphertext: Uint8Array, iv: Uint8Array, protectedHeaders: Uint8Array, context: EncStructureContext, plaintextOffset: number, plaintextLength: number, chunkSize?: number, chunkCount?: number, chunkIndexOffset?: number): Promise<Uint8Array>;
}
/**
 * Derive per-chunk nonce:
 * nonce[0..6]  = base_nonce[0..6]
 * nonce[7..10] = chunk_index (4 bytes, big-endian)
 * nonce[11]    = last_flag (0x00 or 0x01)
 */
declare function deriveChunkNonce(baseNonce: Uint8Array, chunkIndex: number, isLast: boolean): Uint8Array;
export { DEFAULT_CHUNK_SIZE, AES_GCM_TAG_LENGTH, BASE_NONCE_LENGTH, MAX_CHUNK_INDEX, deriveChunkNonce };
//# sourceMappingURL=chunked-aes-256-gcm.d.ts.map