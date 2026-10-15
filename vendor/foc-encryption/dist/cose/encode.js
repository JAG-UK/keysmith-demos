import { Tagged, encode } from 'cborg';
import { COSE_HEADER_ALG, COSE_HEADER_IV, COSE_HEADER_KID, COSE_HEADER_TYP, CoseHeaderParam, FOC_ENVELOPE_TYPE, } from './headers.js';
import { COSE_TAG_ENCRYPT, COSE_TAG_ENCRYPT0 } from './tags.js';
function buildUnprotectedMap(iv, options) {
    const unprotectedMap = new Map([[COSE_HEADER_IV, iv]]);
    if (options?.chunkSize !== undefined) {
        unprotectedMap.set(CoseHeaderParam.CHUNK_SIZE, options.chunkSize);
    }
    if (options?.chunkCount !== undefined) {
        unprotectedMap.set(CoseHeaderParam.CHUNK_COUNT, options.chunkCount);
    }
    if (options?.appMetadata) {
        unprotectedMap.set(CoseHeaderParam.APP_METADATA, encodeAppMetadata(options.appMetadata));
    }
    return unprotectedMap;
}
export function encodeCoseEncrypt0(algorithmId, iv, options) {
    const protectedBytes = getProtectedHeaderBytes(algorithmId);
    const unprotectedMap = buildUnprotectedMap(iv, options);
    return encode(new Tagged(COSE_TAG_ENCRYPT0, [protectedBytes, unprotectedMap, null]));
}
export function encodeCoseEncrypt(algorithmId, iv, recipients, options) {
    const protectedBytes = getProtectedHeaderBytes(algorithmId);
    const unprotectedMap = buildUnprotectedMap(iv, options);
    const recipientStructures = recipients.map((r) => {
        const rProtected = encode(new Map([[COSE_HEADER_ALG, r.algorithm]]));
        const rUnprotected = new Map();
        if (r.keyId) {
            rUnprotected.set(COSE_HEADER_KID, r.keyId);
        }
        if (r.unprotectedHeaders) {
            for (const [k, v] of r.unprotectedHeaders) {
                rUnprotected.set(k, v);
            }
        }
        return [rProtected, rUnprotected, r.wrappedKey];
    });
    return encode(new Tagged(COSE_TAG_ENCRYPT, [protectedBytes, unprotectedMap, null, recipientStructures]));
}
export function getProtectedHeaderBytes(algorithmId) {
    const protectedMap = new Map([
        [COSE_HEADER_ALG, algorithmId],
        [COSE_HEADER_TYP, FOC_ENVELOPE_TYPE],
    ]);
    return encode(protectedMap);
}
function encodeAppMetadata(meta) {
    const map = new Map();
    for (const [key, value] of Object.entries(meta)) {
        if (value !== undefined) {
            map.set(key, value);
        }
    }
    return map;
}
//# sourceMappingURL=encode.js.map