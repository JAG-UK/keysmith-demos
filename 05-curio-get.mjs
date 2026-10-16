/**
 * 5. Retrieval is a plain GET.
 *
 * No SDK, no auth, no chain call: one fetch() against Curio's piece endpoint,
 * then FEE reads the envelope and the key-source layer derives the key. This is
 * the whole point of putting confidentiality in the object — the SP serves
 * ciphertext to anyone, and being "patched" buys an attacker bandwidth only.
 */
import { randomBytes } from 'node:crypto'
import { decryptBytes, readEnvelope } from './lib/fee.mjs'
import { devnet, load, need, note, readBytes, step } from './lib/devnet.mjs'
import * as Keys from './lib/keys.mjs'
import * as Trace from './lib/trace.mjs'
import { pieceUrl } from './lib/store.mjs'

const { sp, users } = devnet()
const state = load()
const cid = need(state, 'pieces', '01-create-dataset.mjs').invoice
const url = pieceUrl(sp.serviceURL, cid)

step('GET the piece — curl would do')
note(`curl -s ${url}`)
const res = await fetch(url)
const blob = new Uint8Array(await res.arrayBuffer())
note(`${res.status} ${res.statusText} · ${blob.length} B · content-type ${res.headers.get('content-type')}`)

step('Anyone can read the envelope; nobody can read the content')
Trace.envelope(blob, 'exactly what the SP served')
const envelope = await readEnvelope(blob)
note(`scheme ${envelope.scheme} · ${envelope.headerLength} B envelope · chunks ${envelope.chunkCount} of ${envelope.chunkSize} B`)
note(`app_metadata ${JSON.stringify(envelope.appMetadata)}`)
note(`recipients in object: ${envelope.recipients.length} (sharing happens off-chain, not in the piece)`)

step('Without the key, that is where it ends')
try {
  await decryptBytes(blob, new Uint8Array(randomBytes(32)))
  console.error('    UNEXPECTED: decrypt succeeded')
} catch (err) {
  note(`decrypt with a wrong key → ${err.constructor.name}`)
}

step('With the grant from demo 3, the same bytes open')
const KK = await Keys.unwrapWith(users[1].private_key_hex, readBytes('grant-dataset.cbor'))
const key = Keys.keyForEnvelope(KK, envelope.appMetadata)
const text = new TextDecoder().decode(await decryptBytes(blob, key))
note(`plaintext: "${text.slice(0, 60)}…"`)

console.log('\nThe retrieval path never changed. Curio, gateways and CDNs stay exactly as they are.')
