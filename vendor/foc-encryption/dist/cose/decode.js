import { Tagged, decode, decodeFirst } from 'cborg';
import { MalformedEnvelopeError } from '../errors.js';
import { COSE_HEADER_ALG, COSE_HEADER_IV, COSE_HEADER_KID, CoseHeaderParam } from './headers.js';
import { COSE_TAG_ENCRYPT, COSE_TAG_ENCRYPT0, coseDecodeOptions } from './tags.js';
export function decodeCoseEnvelope(blob) {
    let decoded;
    let remainder;
    try {
        ;
        [decoded, remainder] = decodeFirst(blob, coseDecodeOptions);
    }
    catch (err) {
        throw new MalformedEnvelopeError('Failed to decode COSE envelope: invalid CBOR', { cause: err });
    }
    if (!(decoded instanceof Tagged)) {
        throw new MalformedEnvelopeError('Expected a CBOR-tagged COSE envelope');
    }
    if (decoded.tag !== COSE_TAG_ENCRYPT0 && decoded.tag !== COSE_TAG_ENCRYPT) {
        throw new MalformedEnvelopeError(`Expected COSE_Encrypt0 (tag 16) or COSE_Encrypt (tag 96), got tag ${decoded.tag}`);
    }
    const arr = decoded.value;
    if (!Array.isArray(arr) || arr.length < 3) {
        throw new MalformedEnvelopeError('COSE envelope must be an array of at least 3 elements');
    }
    const protectedBytes = arr[0];
    const unprotectedMap = arr[1];
    let protectedMap;
    try {
        protectedMap = decode(protectedBytes, { useMaps: true });
    }
    catch (err) {
        throw new MalformedEnvelopeError('Failed to decode protected headers', { cause: err });
    }
    const algorithm = protectedMap.get(COSE_HEADER_ALG);
    if (typeof algorithm !== 'number') {
        throw new MalformedEnvelopeError('Missing or invalid algorithm in protected headers');
    }
    const iv = unprotectedMap.get(COSE_HEADER_IV);
    if (!iv) {
        throw new MalformedEnvelopeError('Missing IV in unprotected headers');
    }
    const chunkSize = unprotectedMap.get(CoseHeaderParam.CHUNK_SIZE);
    const chunkCount = unprotectedMap.get(CoseHeaderParam.CHUNK_COUNT);
    const appMetadata = unprotectedMap.get(CoseHeaderParam.APP_METADATA);
    let recipients = [];
    if (decoded.tag === COSE_TAG_ENCRYPT && arr.length >= 4) {
        const recipientArr = arr[3];
        if (Array.isArray(recipientArr)) {
            recipients = recipientArr.map(parseRecipient);
        }
    }
    const envelopeSize = blob.length - remainder.length;
    return {
        tag: decoded.tag,
        algorithm,
        iv,
        protectedHeaders: protectedBytes,
        chunkSize,
        chunkCount,
        appMetadata,
        recipients,
        envelopeSize,
    };
}
function parseRecipient(arr) {
    const rProtectedBytes = arr[0];
    const rUnprotected = arr[1];
    const wrappedKey = arr[2];
    let rProtected;
    try {
        rProtected = decode(rProtectedBytes, { useMaps: true });
    }
    catch {
        rProtected = new Map();
    }
    const algorithm = rProtected.get(COSE_HEADER_ALG);
    const keyId = rUnprotected.get(COSE_HEADER_KID);
    return {
        algorithm,
        keyId,
        wrappedKey: wrappedKey && wrappedKey.length > 0 ? wrappedKey : undefined,
    };
}
//# sourceMappingURL=decode.js.map