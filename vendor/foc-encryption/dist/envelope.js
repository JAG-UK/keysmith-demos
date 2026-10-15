import { assembleBlob, parseBlob } from './blob.js';
import { decodeCoseEnvelope } from './cose/decode.js';
import { encodeCoseEncrypt, encodeCoseEncrypt0, getProtectedHeaderBytes } from './cose/encode.js';
import { CoseAlgorithm } from './cose/headers.js';
import { COSE_TAG_ENCRYPT, COSE_TAG_ENCRYPT0 } from './cose/tags.js';
import { MalformedEnvelopeError, SchemeNotSeekableError, UnsupportedSchemeError } from './errors.js';
import { importAndZeroCek, validateCek } from './key-utils.js';
import { Aes256Gcm } from './schemes/aes-256-gcm.js';
import { ChunkedAes256GcmStream, DEFAULT_CHUNK_SIZE } from './schemes/chunked-aes-256-gcm.js';
function getScheme(algorithmId, chunkSize) {
    switch (algorithmId) {
        case CoseAlgorithm.AES_256_GCM:
            return new Aes256Gcm();
        case CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM:
            return new ChunkedAes256GcmStream(chunkSize ? { chunkSize } : undefined);
        default:
            throw new UnsupportedSchemeError(algorithmId);
    }
}
/**
 * The COSE Enc_structure context follows the envelope tag (RFC 9052
 * Section 5.3): "Encrypt" for COSE_Encrypt (tag 96) and "Encrypt0" for
 * COSE_Encrypt0 (tag 16).
 */
function encStructureContext(tag) {
    return tag === COSE_TAG_ENCRYPT ? 'Encrypt' : 'Encrypt0';
}
export async function encrypt(plaintext, cek, options, recipients) {
    validateCek(cek);
    const chunkSize = options.algorithm === CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM
        ? options.chunkSize
        : undefined;
    const scheme = getScheme(options.algorithm, chunkSize);
    const protectedHeaders = getProtectedHeaderBytes(options.algorithm);
    const cekCopy = new Uint8Array(cek);
    const key = await importAndZeroCek(cekCopy);
    const envelopeRecipients = recipients?.length ? recipients : undefined;
    const tag = envelopeRecipients ? COSE_TAG_ENCRYPT : COSE_TAG_ENCRYPT0;
    const context = encStructureContext(tag);
    const result = await scheme.encrypt(key, plaintext, protectedHeaders, context, options.appMetadata);
    let envelope;
    const encodeOpts = {
        appMetadata: options.appMetadata,
        chunkSize: result.chunkSize,
        chunkCount: result.chunkCount,
    };
    if (envelopeRecipients) {
        for (const r of envelopeRecipients) {
            if (!r.wrappedKey || r.wrappedKey.length === 0) {
                throw new MalformedEnvelopeError('Recipient must have a non-empty wrappedKey');
            }
        }
        envelope = encodeCoseEncrypt(options.algorithm, result.iv, envelopeRecipients, encodeOpts);
    }
    else {
        envelope = encodeCoseEncrypt0(options.algorithm, result.iv, encodeOpts);
    }
    return assembleBlob(envelope, result.ciphertext);
}
export async function decrypt(blob, cek) {
    const parsed = parseBlob(blob);
    const envelope = decodeCoseEnvelope(parsed.envelopeBytes);
    const scheme = getScheme(envelope.algorithm, envelope.chunkSize);
    const cekCopy = new Uint8Array(cek);
    const key = await importAndZeroCek(cekCopy);
    const context = encStructureContext(envelope.tag);
    const metadata = { chunkSize: envelope.chunkSize, chunkCount: envelope.chunkCount };
    return scheme.decrypt(key, parsed.ciphertext, envelope.iv, envelope.protectedHeaders, context, metadata);
}
export async function decryptRange(fetcher, metadata, cek, range) {
    const scheme = getScheme(metadata.algorithm, metadata.chunkSize);
    if (!scheme.isSeekable) {
        throw new SchemeNotSeekableError(`Scheme ${scheme.name} (algorithm ${scheme.algorithmId}) does not support range decryption`);
    }
    const cekCopy = new Uint8Array(cek);
    const key = await importAndZeroCek(cekCopy);
    const chunkedScheme = scheme;
    const effectiveChunkSize = metadata.chunkSize ?? DEFAULT_CHUNK_SIZE;
    const tagLength = 16;
    const ciphertextChunkSize = effectiveChunkSize + tagLength;
    const firstChunk = Math.floor(range.offset / effectiveChunkSize);
    const lastChunk = Math.min(Math.floor((range.offset + range.length - 1) / effectiveChunkSize), (metadata.chunkCount ?? 1) - 1);
    const ctStart = metadata.envelopeSize + firstChunk * ciphertextChunkSize;
    const ctEnd = lastChunk === (metadata.chunkCount ?? 1) - 1
        ? undefined // fetch to end for last chunk (may be shorter)
        : metadata.envelopeSize + (lastChunk + 1) * ciphertextChunkSize;
    const fetchLength = ctEnd !== undefined ? ctEnd - ctStart : (lastChunk - firstChunk + 1) * ciphertextChunkSize; // overfetch last chunk is OK
    const fetched = await fetcher.fetchRange(ctStart, fetchLength);
    const context = encStructureContext(metadata.tag);
    return chunkedScheme.decryptRange(key, fetched, metadata.iv, metadata.protectedHeaders, context, range.offset - firstChunk * effectiveChunkSize, range.length, effectiveChunkSize, metadata.chunkCount, firstChunk);
}
function parseEnvelopeBytes(blob) {
    let envelope;
    try {
        envelope = decodeCoseEnvelope(blob);
    }
    catch (e) {
        if (e instanceof MalformedEnvelopeError)
            throw e;
        throw new MalformedEnvelopeError('Failed to parse envelope');
    }
    const seekable = envelope.algorithm === CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM;
    let appMetadata;
    if (envelope.appMetadata) {
        appMetadata = Object.fromEntries(envelope.appMetadata);
    }
    return {
        tag: envelope.tag,
        algorithm: envelope.algorithm,
        seekable,
        iv: envelope.iv,
        protectedHeaders: envelope.protectedHeaders,
        chunkSize: envelope.chunkSize,
        chunkCount: envelope.chunkCount,
        appMetadata,
        recipients: envelope.recipients,
        envelopeSize: envelope.envelopeSize,
    };
}
export function parseEnvelope(blob) {
    if (blob instanceof Uint8Array) {
        return parseEnvelopeBytes(blob);
    }
    return blob.fetchEnvelope().then(parseEnvelopeBytes);
}
//# sourceMappingURL=envelope.js.map