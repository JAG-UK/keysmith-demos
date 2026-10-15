import type { DecryptMetadata, EncStructureContext, EncryptResult, EncryptionScheme } from './scheme.js';
declare const AES_GCM_IV_LENGTH = 12;
declare const AES_GCM_TAG_LENGTH = 16;
export declare class Aes256Gcm implements EncryptionScheme {
    readonly name = "AES-256-GCM";
    readonly algorithmId = 3;
    readonly isSeekable = false;
    encrypt(key: CryptoKey, plaintext: Uint8Array, protectedHeaders: Uint8Array, context: EncStructureContext): Promise<EncryptResult>;
    decrypt(key: CryptoKey, ciphertext: Uint8Array, iv: Uint8Array, protectedHeaders: Uint8Array, context: EncStructureContext, _metadata?: DecryptMetadata): Promise<Uint8Array>;
}
export { AES_GCM_IV_LENGTH, AES_GCM_TAG_LENGTH };
//# sourceMappingURL=aes-256-gcm.d.ts.map