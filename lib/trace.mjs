/**
 * Verbose tracing. Off by default; `FOC_VERBOSE=1` or `--verbose` turns it on.
 *
 * Prints the actual bytes: COSE envelope structure with its CDDL, CBOR in
 * diagnostic notation, every HKDF input and output, the ECDH/AES-GCM steps of a
 * grant, and the per-chunk nonce derivation FEE uses to decrypt.
 *
 * Nothing here is part of the design — it is a window onto it.
 */
import { Tagged, decode, decodeFirst, encode } from 'cborg'

export const VERBOSE =
  process.env.FOC_VERBOSE === '1' || process.argv.includes('--verbose') || process.argv.includes('-v')

const COSE_TAG_ENCRYPT0 = 16
const COSE_TAG_ENCRYPT = 96
const OPTS = { tags: Tagged.preserve(COSE_TAG_ENCRYPT0, COSE_TAG_ENCRYPT), useMaps: true }

/** COSE header labels FEE uses. Negative ones are its private-use extensions. */
const LABEL = {
  1: 'alg',
  4: 'kid',
  5: 'IV',
  16: 'typ',
  '-65790': 'chunk_size',
  '-65791': 'chunk_count',
  '-65792': 'app_metadata',
}
const ALG = {
  3: 'A256GCM',
  '-65793': 'Chunked-AES-256-GCM-STREAM',
  '-31': 'ECDH-ES+A256KW',
}

const BAR = '    │ '
const dim = (s) => (process.stdout.isTTY ? `\x1b[2m${s}\x1b[0m` : s)

export function say(...lines) {
  if (!VERBOSE) return
  for (const line of lines.flat()) console.log(BAR + line)
}

export function title(text) {
  if (!VERBOSE) return
  console.log(`${BAR}${dim('─'.repeat(4))} ${text} ${dim('─'.repeat(Math.max(0, 62 - text.length)))}`)
}

export function cddl(text) {
  if (!VERBOSE) return
  for (const line of text.trim().split('\n')) console.log(BAR + dim(line))
}

export const hex = (b) => Buffer.from(b ?? []).toString('hex')

export function bytes(label, b, max = 32) {
  if (!VERBOSE) return
  const buf = Buffer.from(b ?? [])
  const shown = buf.subarray(0, max).toString('hex')
  say(`${label} (${buf.length} B) ${shown}${buf.length > max ? '…' : ''}`)
}

/** CBOR diagnostic notation, RFC 8949 §8: h'' for bytes, #6.n(...) for tags. */
export function diag(value) {
  if (value === null) return 'null'
  if (value instanceof Tagged) return `#6.${value.tag}(${diag(value.value)})`
  if (value instanceof Uint8Array) {
    const h = Buffer.from(value).toString('hex')
    return `h'${h.length > 48 ? `${h.slice(0, 48)}…` : h}'`
  }
  if (Array.isArray(value)) return `[${value.map(diag).join(', ')}]`
  if (value instanceof Map) {
    const entries = [...value.entries()].map(([k, v]) => {
      const name = LABEL[String(k)]
      return `${diag(k)}${name ? dim(`/${name}/`) : ''}: ${diag(v)}`
    })
    return `{${entries.join(', ')}}`
  }
  if (typeof value === 'string') return JSON.stringify(value)
  return String(value)
}

/** Full anatomy of a FEE blob: envelope, headers, recipients, chunk layout. */
export function envelope(blob, label = 'FEE blob') {
  if (!VERBOSE) return
  title(label)
  cddl(`
; RFC 9052 §5, as FEE uses it. The blob is [COSE envelope][ciphertext].
COSE_Encrypt0 = #6.16([ protected: bstr .cbor header_map, unprotected: header_map, null ])
COSE_Encrypt  = #6.96([ protected, unprotected, null, recipients: [+ COSE_recipient] ])
COSE_recipient = [ protected: bstr .cbor {1: alg}, unprotected: {4: kid, ...}, encrypted_key: bstr ]
header_map = { 1 => alg, 5 => IV, -65790 => chunk_size, -65791 => chunk_count, -65792 => app_metadata }`)

  const [tagged, rest] = decodeFirst(blob, OPTS)
  const envelopeSize = blob.length - rest.length
  const [protectedBytes, unprotected, detached, recipients] = tagged.value

  say(
    `tag ${tagged.tag} (${tagged.tag === COSE_TAG_ENCRYPT0 ? 'COSE_Encrypt0' : 'COSE_Encrypt'}) · envelope ${envelopeSize} B · ciphertext ${rest.length} B`,
    `diagnostic: ${diag(tagged)}`
  )

  const prot = protectedBytes.length ? decode(protectedBytes, OPTS) : new Map()
  bytes('protected (bstr, AAD-covered)', protectedBytes)
  say(`protected decoded: ${diag(prot)}`)
  const alg = prot.get(1)
  say(`alg ${alg} = ${ALG[String(alg)] ?? 'unknown'}`)
  say(`unprotected: ${diag(unprotected)}`)
  say(`detached ciphertext slot: ${diag(detached)}`)

  const meta = unprotected.get(-65792)
  if (meta) {
    say('app_metadata (unprotected in this build; #967 moves it under protected):')
    for (const [k, v] of meta.entries()) say(`  ${JSON.stringify(k)} => ${diag(v)}`)
  }

  if (recipients?.length) {
    say(`recipients: ${recipients.length}`)
    for (const [i, r] of recipients.entries()) {
      const rProt = r[0]?.length ? decode(r[0], OPTS) : new Map()
      say(`  [${i}] alg ${rProt.get(1)} = ${ALG[String(rProt.get(1))] ?? '?'} · unprotected ${diag(r[1])}`)
      bytes(`  [${i}] encrypted_key`, r[2])
    }
  } else {
    say('recipients: none — this is COSE_Encrypt0, sharing happens outside the object')
  }

  const iv = unprotected.get(5)
  const chunkSize = unprotected.get(-65790)
  const chunkCount = unprotected.get(-65791)
  bytes('base nonce (IV)', iv)
  if (chunkSize != null) {
    say(
      `chunk_size ${chunkSize} B · chunk_count ${chunkCount} · tag overhead ${chunkCount * 16} B`,
      'per-chunk nonce = base[0..6] ‖ uint32be(index) ‖ last_flag',
      'decryption walks this table; a range read touches only the chunks it overlaps:'
    )
    let ct = envelopeSize
    let pt = 0
    for (let i = 0; i < Math.min(chunkCount, 4); i++) {
      const last = i === chunkCount - 1
      const ptLen = last ? rest.length - 16 * chunkCount - chunkSize * (chunkCount - 1) : chunkSize
      const nonce = `${hex(iv.subarray(0, 7))} ${i.toString(16).padStart(8, '0')} ${last ? '01' : '00'}`
      say(
        `  #${i} plaintext [${pt}..${pt + ptLen}) ← blob [${ct}..${ct + ptLen + 16}) = ${ptLen} B + 16 B tag · nonce ${nonce}`
      )
      ct += ptLen + 16
      pt += ptLen
    }
    if (chunkCount > 4) say(`  … ${chunkCount - 4} more chunks`)
  }
  const aad = encode([
    tagged.tag === COSE_TAG_ENCRYPT0 ? 'Encrypt0' : 'Encrypt',
    protectedBytes,
    new Uint8Array(0),
  ])
  cddl('Enc_structure = [ context: "Encrypt0" / "Encrypt", protected: bstr, external_aad: bstr ]')
  bytes('AAD (Enc_structure, CBOR)', aad)
}

export function hkdf(name, { ikm, info, out }) {
  if (!VERBOSE) return
  say(`HKDF-SHA256 → ${name}`)
  bytes('  IKM ', ikm)
  say(`  info  "${info}"`)
  bytes('  out ', out)
}

export function eip712(domain, types, message, signature, rs) {
  if (!VERBOSE) return
  title('EIP-712 DatasetKey')
  say(`domain ${JSON.stringify(domain)}`)
  say(`types  ${JSON.stringify(types.DatasetKey.map((f) => `${f.type} ${f.name}`))}`)
  for (const [k, v] of Object.entries(message)) say(`  ${k}: ${v}`)
  bytes('signature (65 B, r‖s‖v)', Buffer.from(signature.slice(2), 'hex'))
  bytes('key material (r‖s, low-S, v dropped)', rs)
}

export function ecdh(kind, { epk, pkR, shared, kek, aad, iv, ct }) {
  if (!VERBOSE) return
  title(`${kind} · ECDH-ES + AES-256-GCM over secp256k1`)
  bytes('ephemeral public key (epk)', epk)
  bytes('recipient key-agreement key (pkR)', pkR)
  say('  pkR is derived from the recipient’s signing key: HKDF(key, "foc/acl/ecdh/v1") → hash-to-scalar')
  bytes('ECDH shared secret (x-coordinate)', shared)
  say('KEK = HKDF-SHA256(shared ‖ epk ‖ pkR, info "foc/acl/wrap/v1")')
  bytes('KEK', kek)
  say(`AAD = canonical descriptor JSON: ${aad}`)
  bytes('GCM nonce', iv)
  bytes('wrapped key (ct ‖ tag)', ct)
}

export function http(method, url, extra = '') {
  if (!VERBOSE) return
  say(`${method} ${url} ${extra}`.trim())
}

export function chain(fn, args, result) {
  if (!VERBOSE) return
  say(`eth_call ${fn}(${args.join(', ')}) → ${result}`)
}
