import type { CoseEnvelopeTag, RecipientInfo } from '../types.js';
export interface DecodedEnvelope {
    tag: CoseEnvelopeTag;
    algorithm: number;
    iv: Uint8Array;
    protectedHeaders: Uint8Array;
    chunkSize?: number;
    chunkCount?: number;
    appMetadata?: Map<string, unknown>;
    recipients: RecipientInfo[];
    envelopeSize: number;
}
export declare function decodeCoseEnvelope(blob: Uint8Array): DecodedEnvelope;
//# sourceMappingURL=decode.d.ts.map