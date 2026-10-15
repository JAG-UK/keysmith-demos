import type { AppMetadata, Recipient } from '../types.js';
interface EncodeOptions {
    appMetadata?: AppMetadata;
    chunkSize?: number;
    chunkCount?: number;
}
export declare function encodeCoseEncrypt0(algorithmId: number, iv: Uint8Array, options?: EncodeOptions): Uint8Array;
export declare function encodeCoseEncrypt(algorithmId: number, iv: Uint8Array, recipients: Recipient[], options?: EncodeOptions): Uint8Array;
export declare function getProtectedHeaderBytes(algorithmId: number): Uint8Array;
export {};
//# sourceMappingURL=encode.d.ts.map