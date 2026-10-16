/**
 * 6. Recovery from nothing but the wallet — wherever the copies ended up.
 *
 * Delete every local file, every grant, every note. Then walk every dataset
 * this wallet pays for and open every piece in it. Each piece's envelope names
 * its keyspace, so the key comes from the envelope, not from the dataset it was
 * found in: a copy that replication or repair put into some other dataset opens
 * exactly like the original. One signature per distinct keyspace, however many
 * datasets it is spread across; foc/kc is checked wherever a dataset recorded it.
 *
 * This demo reads NOTHING from out/state.json.
 */
import { getAllDataSetMetadata, getClientDataSets } from '@filoz/synapse-core/warm-storage'
import { decryptBytes, readEnvelope } from './lib/fee.mjs'
import { clientFor, devnet, note, step } from './lib/devnet.mjs'
import * as Keys from './lib/keys.mjs'
import { getPiece, listPiecesOnChain } from './lib/store.mjs'
import * as Trace from './lib/trace.mjs'

const { sp, users, chain } = devnet()
const payer = users[0]
const client = clientFor(payer.private_key_hex, chain)

/**
 * keyspace → { kk, commitment }: one signature per keyspace, however many datasets it spans.
 * Signed once, not twice: the dataset's commitment checks the key instead.
 */
const keyspaces = new Map()
async function keysFor(keyspace, recorded) {
  if (!keyspaces.has(keyspace)) {
    note(`  signing for keyspace ${keyspace} — the only prompt it will ever cost this run`)
    keyspaces.set(keyspace, await Keys.keyspaceKeys(client.account, { owner: payer.evm_addr, keyspace }, { commitment: recorded }))
  }
  return keyspaces.get(keyspace)
}

step('Ask the chain what this wallet pays for')
const page = await getClientDataSets(client, { address: payer.evm_addr })
note(`${page.items.length} dataset(s) for ${payer.evm_addr}`)

for (const { dataSetId } of page.items) {
  step(`Dataset ${dataSetId}`)
  const metadata = await getAllDataSetMetadata(client, { dataSetId: BigInt(dataSetId) })
  const recorded = metadata['foc/ks']
  note(recorded ? `records keyspace ${recorded}` : 'records no keyspace — pieces will say for themselves')

  if (recorded && metadata['foc/kc']) {
    // Checked before signing, so a dataset from a pre-release format costs no prompt.
    if (!/^v1\.[0-9a-f]{32}$/.test(metadata['foc/kc'])) {
      note(`a pre-release commitment (${metadata['foc/kc'].slice(0, 8)}…); skipping this dataset`)
      continue
    }
    try {
      await keysFor(recorded, metadata['foc/kc'])
    } catch (err) {
      note(`foc/kc MISMATCH — ${err.message}. Stopping loudly, not decrypting garbage.`)
      continue
    }
    note('foc/kc matches: the right key, before a single byte is decrypted')
  }

  for (const piece of await listPiecesOnChain(client, dataSetId)) {
    const blob = await getPiece(sp.serviceURL, piece.pieceCid)
    Trace.envelope(blob, `piece ${piece.pieceId}`)
    let appMetadata
    try {
      ;({ appMetadata } = await readEnvelope(blob))
    } catch {
      note(`  piece ${piece.pieceId} — not a FEE envelope (plaintext piece), skipping`)
      continue
    }
    if (appMetadata?.['foc/v'] !== 1 || !appMetadata['foc/ks']) {
      note(`  piece ${piece.pieceId} — not a Keysmith envelope (foc/v ${appMetadata?.['foc/v']}); skipping`)
      continue
    }
    const keyspace = appMetadata['foc/ks']
    const where = keyspace === recorded ? '' : `  ← written under keyspace ${keyspace.slice(0, 10)}…, found here`
    const { kk } = await keysFor(keyspace)
    const scope = appMetadata['foc/scope'] ?? '(no scope)'
    const text = new TextDecoder().decode(await decryptBytes(blob, Keys.keyForEnvelope(kk, appMetadata)))
    note(`  piece ${piece.pieceId} [${scope}] → "${text.slice(0, 40)}…"${where}`)
  }
}

console.log(`\n${keyspaces.size} keyspace(s), ${keyspaces.size} signature(s). No keystore, no backup file, no service.`)
console.log('The envelope names the keyspace, so it did not matter which dataset a copy was found in.')
