export declare function assembleBlob(envelope: Uint8Array, ciphertext: Uint8Array): Uint8Array;
export interface ParsedBlob {
    envelopeBytes: Uint8Array;
    envelopeValue: unknown;
    ciphertext: Uint8Array;
}
export declare function parseBlob(blob: Uint8Array): ParsedBlob;
//# sourceMappingURL=blob.d.ts.map