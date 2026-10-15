export declare function getRandomValues(length: number): Uint8Array;
export declare function aesGcmEncrypt(key: CryptoKey, iv: Uint8Array, plaintext: Uint8Array, additionalData: Uint8Array): Promise<Uint8Array>;
export declare function aesGcmDecrypt(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array, additionalData: Uint8Array): Promise<Uint8Array>;
export declare function importAesGcmKey(rawKey: Uint8Array): Promise<CryptoKey>;
//# sourceMappingURL=crypto.d.ts.map