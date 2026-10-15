import type { BlobFetcher, ByteRange, CEKBytes, EncryptOptions, EnvelopeMetadata, Recipient } from './types.js';
export declare function encrypt(plaintext: Uint8Array, cek: CEKBytes, options: EncryptOptions, recipients?: Recipient[]): Promise<Uint8Array>;
export declare function decrypt(blob: Uint8Array, cek: CEKBytes): Promise<Uint8Array>;
export declare function decryptRange(fetcher: BlobFetcher, metadata: EnvelopeMetadata, cek: CEKBytes, range: ByteRange): Promise<Uint8Array>;
export declare function parseEnvelope(blob: Uint8Array): EnvelopeMetadata;
export declare function parseEnvelope(fetcher: BlobFetcher): Promise<EnvelopeMetadata>;
//# sourceMappingURL=envelope.d.ts.map