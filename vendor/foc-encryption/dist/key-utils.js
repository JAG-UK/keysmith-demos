import { importAesGcmKey } from './crypto.js';
import { InvalidKeyError } from './errors.js';
export function validateCek(cek) {
    if (cek.length !== 32) {
        throw new InvalidKeyError(`CEK must be exactly 32 bytes, got ${cek.length}`);
    }
    if (cek.every((b) => b === 0)) {
        throw new InvalidKeyError('CEK must not be all zeros');
    }
}
export async function importAndZeroCek(cek) {
    validateCek(cek);
    const key = await importAesGcmKey(cek);
    zeroBuffer(cek);
    return key;
}
export function zeroBuffer(buf) {
    buf.fill(0);
}
//# sourceMappingURL=key-utils.js.map