import * as cborg from 'cborg';
import { coseDecodeOptions } from './cose/tags.js';
export function assembleBlob(envelope, ciphertext) {
    const blob = new Uint8Array(envelope.length + ciphertext.length);
    blob.set(envelope, 0);
    blob.set(ciphertext, envelope.length);
    return blob;
}
export function parseBlob(blob) {
    const [value, remainder] = cborg.decodeFirst(blob, coseDecodeOptions);
    const envelopeSize = blob.length - remainder.length;
    return {
        envelopeBytes: blob.slice(0, envelopeSize),
        envelopeValue: value,
        ciphertext: remainder,
    };
}
//# sourceMappingURL=blob.js.map