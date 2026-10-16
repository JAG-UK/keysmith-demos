/**
 * FEE, the published `filecoin-encryption-envelope`, behind three byte-oriented
 * helpers so the demos read as steps. FEE itself is streaming: these just run a
 * whole object through `fee.encrypt()` / `fee.decrypt()`.
 */
import * as fee from 'filecoin-encryption-envelope'

export { fee }

/** Run bytes through a FEE stream and collect the result, keeping FEE's own errors. */
async function through(bytes, transform) {
  const reader = new Blob([bytes]).stream().pipeThrough(transform).getReader()
  const chunks = []
  for (let next = await reader.read(); !next.done; next = await reader.read()) chunks.push(next.value)
  const out = new Uint8Array(chunks.reduce((n, chunk) => n + chunk.length, 0))
  let at = 0
  for (const chunk of chunks) {
    out.set(chunk, at)
    at += chunk.length
  }
  return out
}

/** Chunked AES-256-GCM, with Keysmith's labels as authenticated `app_metadata` and the length committed. */
export const encryptBytes = (plaintext, cek, appMetadata) =>
  through(plaintext, fee.encrypt({ cek, appMetadata, contentLength: plaintext.length }))

/** `key` is the piece key, or a resolver that derives it from the envelope (Keysmith's `keyResolver`). */
export const decryptBytes = (blob, key) => through(blob, fee.decrypt(key))

/** An in-memory object, in the shape FEE reads envelopes and ranges from. */
export const memorySource = (bytes) => ({
  size: bytes.length,
  openRange: async (offset, length) => new Blob([bytes.subarray(offset, offset + length)]).stream(),
})

/**
 * The envelope, read without a key: scheme, chunk layout, and Keysmith's labels
 * as a plain object. Not authenticated until a content tag verifies.
 */
export async function readEnvelope(blob) {
  const info = await fee.parse(memorySource(blob))
  const params = info.scheme === 'chunked' ? info.params : undefined
  const chunkCount = params ? Math.ceil((blob.length - params.headerLength) / (params.chunkSize + 16)) : 1
  return {
    scheme: info.scheme,
    headerLength: params?.headerLength,
    chunkSize: params?.chunkSize,
    chunkCount,
    plaintextLength: params?.plaintextLength,
    appMetadata: info.appMetadata ? { ...info.appMetadata } : undefined,
    recipients: info.recipients,
  }
}
