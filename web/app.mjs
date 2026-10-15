/**
 * 7. The same story from a browser wallet: start a key hierarchy from MetaMask,
 * write, delegate to an agent, and recover from nothing.
 *
 * Every wallet prompt is announced in the log before MetaMask shows it. Keys
 * live in this tab's memory only; the one thing stored is a note that this
 * wallet has already proved it signs deterministically, which saves a prompt.
 *
 * Layers: @filoz/keysmith derives · FEE encrypts · Curio stores · FWSS records.
 */
import * as Keysmith from '@filoz/keysmith'
import * as SessionKey from '@filoz/synapse-core/session-key'
import { toChain } from '@filoz/synapse-core/devnet'
import { getAllDataSetMetadata, getClientDataSets, getDataSet } from '@filoz/synapse-core/warm-storage'
import { Synapse } from '@filoz/synapse-sdk'
import { CoseAlgorithm, decrypt, encrypt, parseEnvelope } from 'foc-encryption'
import {
  createClient,
  custom,
  formatEther,
  formatUnits,
  http,
  numberToHex,
  parseUnits,
  publicActions,
  walletActions,
} from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { addPiece, createDataSetWithPiece, getPiece, listPiecesOnChain, putPiece } from '../lib/store.mjs'

const devnet = await (await fetch('/devnet.json')).json()
const runId = devnet.info.run_id
const lotus = devnet.info.lotus.host_rpc_url
const sp = { serviceURL: devnet.info.pdp_sps[0].pdp_service_url, payee: devnet.info.pdp_sps[0].eth_addr }
// The page reads through the dev server, because Lotus sends no CORS headers. MetaMask talks to Lotus itself.
const proxied = { http: [`${location.origin}/rpc/v1`] }
const chain = { ...toChain(devnet), rpcUrls: { default: proxied, public: proxied } }
const reader = createClient({ chain, transport: http() }).extend(publicActions)

const SCOPE = 'agent-memory'
/** The Filecoin Pay console, run locally against the devnet (see README). */
const CONSOLE = 'http://localhost:3780'
const ALGORITHM = CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM
const $ = (id) => document.getElementById(id)
const utf8 = (text) => new TextEncoder().encode(text)
const short = (hex) => `${hex.slice(0, 10)}…`

const state = { owner: null, wallet: null, signer: null, signatures: 0, current: null, dataSet: null }
/** keyspace → { kk, commitment, descriptor }. Memory only: a reload forgets it. */
const keyspaces = new Map()

// ── keys: one signature per keyspace ────────────────────────────────────────

/**
 * Keysmith signs twice on a signer's first use and compares, to catch a wallet
 * that randomises its signatures. Within a page load it remembers that per
 * signer object; across reloads, the app has to remember it per address.
 */
const vettedKey = (owner) => `keysmith:vetted:${owner.toLowerCase()}`
function vetted(owner) {
  try {
    return localStorage.getItem(vettedKey(owner)) === '1'
  } catch {
    return false
  }
}
function markVetted(owner) {
  try {
    localStorage.setItem(vettedKey(owner), '1')
  } catch {
    // private window: the next page load checks again, at the cost of one prompt
  }
}

/** One signature per keyspace. */
/** `commitment`, for an existing keyspace: sign once, and let the dataset's `foc/kc` check the key. */
async function keysFor(keyspace, commitment) {
  if (!keyspaces.has(keyspace)) {
    const known = commitment != null || vetted(state.owner)
    const which = `keyspace ${short(keyspace)}`
    prompt(
      known
        ? `sign KeyspaceKey for ${which}`
        : `sign KeyspaceKey for ${which}, twice: the first time, Keysmith checks this wallet gives the same signature both times`
    )
    const ref = { owner: state.owner, keyspace }
    const options = commitment != null ? { commitment } : vetted(state.owner) ? { verifySigner: false } : {}
    keyspaces.set(keyspace, await Keysmith.keyspaceKeys(state.signer, ref, options))
    markVetted(state.owner)
  }
  return keyspaces.get(keyspace)
}

// ── 1. connect ──────────────────────────────────────────────────────────────

on('connect', async () => {
  if (!window.ethereum) throw new Error('No browser wallet found. Install MetaMask, then reload.')
  prompt('connect an account to this page')
  const [owner] = await window.ethereum.request({ method: 'eth_requestAccounts' })
  await switchToDevnet()
  state.owner = owner
  state.wallet = createClient({ chain, transport: custom(window.ethereum), account: owner })
    .extend(publicActions)
    .extend(walletActions)
  // Keysmith calls this; counting here shows what the key hierarchy costs in prompts.
  state.signer = {
    signTypedData: (args) => {
      $('count').textContent = ++state.signatures
      return state.wallet.signTypedData(args)
    },
  }
  window.ethereum.on?.('accountsChanged', () => location.reload())
  window.ethereum.on?.('chainChanged', () => location.reload())

  const fil = await reader.getBalance({ address: owner })
  $('who').textContent = owner
  log(`Connected ${owner} on devnet ${runId} · ${formatEther(fil)} FIL`)
  if (fil === 0n) log('This account has no devnet FIL: import a devnet user key into MetaMask (see README).', 'error')
  log(
    vetted(owner)
      ? 'This browser has seen this wallet sign deterministically before: one signature per keyspace.'
      : 'First time this browser has seen this wallet: its first keyspace costs two identical signatures.',
    'dim'
  )
})

async function switchToDevnet() {
  const chainId = numberToHex(chain.id)
  if ((await window.ethereum.request({ method: 'eth_chainId' })) === chainId) return
  try {
    prompt('switch network to the FOC devnet')
    await window.ethereum.request({ method: 'wallet_switchEthereumChain', params: [{ chainId }] })
  } catch (err) {
    if (err?.code !== 4902) throw err
    prompt(`add network "${chain.name}" (chain ${chain.id}, RPC ${lotus})`)
    await window.ethereum.request({
      method: 'wallet_addEthereumChain',
      params: [{ chainId, chainName: chain.name, nativeCurrency: chain.nativeCurrency, rpcUrls: [lotus] }],
    })
  }
}

// ── 2. start a keyspace ─────────────────────────────────────────────────────

on('keyspace', async () => {
  const ref = { owner: state.owner, keyspace: Keysmith.newKeyspace() }
  log(`New keyspace ${ref.keyspace}: random, and with the wallet the only input to every key.`)
  const request = { domain: Keysmith.DOMAIN, primaryType: 'KeyspaceKey', message: Keysmith.keyspaceKeyMessage(ref) }
  $('typed').textContent = JSON.stringify(request, null, 2)
  $('typed-box').open = true
  const { commitment } = await keysFor(ref.keyspace)
  state.current = ref
  state.dataSet = null
  log(`Keyspace key derived, in this tab only. Commitment ${commitment}: the one trace that goes on chain.`, 'ok')
})

// ── 3. create a dataset ─────────────────────────────────────────────────────

on('create', async () => {
  const { kk, commitment, descriptor } = await keysFor(state.current.keyspace)
  // The owner writes the way a delegate does: the keyspace comes from what was signed.
  const target = Keysmith.writeTarget(descriptor, kk)
  const salt = Keysmith.newSalt()
  const ciphertext = await encrypt(utf8($('first').value), Keysmith.pieceKey(target.key, salt), {
    algorithm: ALGORITHM,
    appMetadata: Keysmith.pieceMetadata(target.ref, { salt, scope: target.scope }),
  })
  log(`Encrypted in the tab: ${ciphertext.length} B envelope. No prompt.`)

  await fund()
  log('Uploading to the SP, and waiting until it has stored the piece. No prompt; this can take a minute.', 'dim')
  const pieceCid = await putPiece(sp.serviceURL, ciphertext)
  log(`Uploaded the ciphertext to the SP: ${pieceCid}. The SP never sees a key.`)

  prompt('sign "create dataset and add pieces" for Warm Storage: the SP submits it and pays the gas')
  const created = await createDataSetWithPiece(state.wallet, {
    serviceURL: sp.serviceURL,
    payee: sp.payee,
    metadata: { [Keysmith.KEYSPACE_ID_KEY]: state.current.keyspace, [Keysmith.COMMITMENT_KEY]: commitment },
    pieceCid,
  })
  // Only addPieces needs this, and only because FWSS signs over it. No key depends on it.
  const { clientDataSetId } = await getDataSet(reader, { dataSetId: created.dataSetId })
  state.dataSet = { id: created.dataSetId, clientDataSetId }
  log(`Dataset ${created.dataSetId} created; its first piece is live.`, 'ok')
})

/** Ordinary Synapse payment setup, the same as demo 1. Nothing to do with keys. */
async function fund() {
  // Lotus refuses even a read "from" an address it has never seen, so say why rather than fail obscurely.
  if ((await reader.getBalance({ address: state.owner })) === 0n) {
    throw new Error('This account has no devnet FIL, so the chain does not know it yet. Import a devnet user key into MetaMask (see README).')
  }
  const synapse = Synapse.create({ chain, transport: custom(window.ethereum), account: state.owner })
  // Each half is checked on its own, so a run interrupted between them resumes where it stopped.
  const { availableFunds } = await synapse.payments.accountInfo()
  if (availableFunds < parseUnits('2', 18)) {
    prompt('payment setup: allow FilecoinPay to take 10 USDFC (if not already allowed), then deposit it')
    const deposit = await synapse.payments.deposit({ amount: parseUnits('10', 18) })
    await reader.waitForTransactionReceipt({ hash: deposit })
    log('Deposited 10 USDFC.', 'ok')
  } else {
    log(`Storage account holds ${formatUnits(availableFunds, 18)} USDFC.`, 'dim')
  }
  if (!(await synapse.payments.serviceApproval()).isApproved) {
    prompt('payment setup: approve Warm Storage as an operator, so it can charge for storage')
    const approval = await synapse.payments.approveService({})
    await reader.waitForTransactionReceipt({ hash: approval })
    log('Approved Warm Storage.', 'ok')
  }
}

// ── 4. delegate to an agent ─────────────────────────────────────────────────

on('delegate', async () => {
  const { kk } = await keysFor(state.current.keyspace)
  const sessionPrivateKey = generatePrivateKey()
  const session = privateKeyToAccount(sessionPrivateKey)
  if ($('via-console').checked) {
    await authoriseInConsole(session.address)
  } else {
    prompt(`send SessionKeyRegistry.login: lets ${short(session.address)} add pieces for one hour, and nothing else`)
    await SessionKey.loginSync(state.wallet, {
      address: session.address,
      permissions: [SessionKey.AddPiecesPermission],
      expiresAt: BigInt(Math.floor(Date.now() / 1000) + 3600),
    })
  }
  const descriptor = Keysmith.grantDescriptor(state.current, `scope:${SCOPE}`)
  const grant = await Keysmith.wrapTo(Keysmith.publicKeyOf(sessionPrivateKey), Keysmith.scopeKey(kk, SCOPE), descriptor)
  log(`Wrapped the "${SCOPE}" scope key to the session key. No prompt: the keyspace key was already in the tab.`)

  // The agent's side: it holds its own key and the grant, never the wallet.
  const target = Keysmith.writeTarget(grant, await Keysmith.unwrapWith(sessionPrivateKey, grant))
  const salt = Keysmith.newSalt()
  const ciphertext = await encrypt(utf8($('agent').value), Keysmith.pieceKey(target.key, salt), {
    algorithm: ALGORITHM,
    appMetadata: Keysmith.pieceMetadata(target.ref, { salt, scope: target.scope }),
  })
  const agent = createClient({ chain, transport: http(), account: session }).extend(publicActions)
  log('Uploading to the SP, and waiting until it has stored the piece. No prompt; this can take a minute.', 'dim')
  const pieceCid = await putPiece(sp.serviceURL, ciphertext)
  await addPiece(agent, {
    serviceURL: sp.serviceURL,
    dataSetId: state.dataSet.id,
    clientDataSetId: state.dataSet.clientDataSetId,
    pieceCid,
  })
  log(`The agent wrote ${pieceCid} under "${target.scope}", signing as the session key. No prompt.`, 'ok')
})

/**
 * Send the owner to the Filecoin Pay console to authorise the agent's key, the
 * way `filecoin-pin session create --console` does, then wait for the chain to
 * show it. The console is a separate app: the only thing passed is the link.
 */
async function authoriseInConsole(sessionAddress) {
  const link = `${CONSOLE}/console/session-keys?authorize=${sessionAddress}&scopes=addPieces&network=devnet`
  // Before any await, so the browser still counts it as part of the click and does not block it.
  window.open(link, '_blank')
  log('Opened the Filecoin Pay console. If no tab appeared, open: ', 'dim', link)
  prompt('in the console tab: connect this same wallet, approve "Add pieces" for the agent key, then confirm one transaction')
  const deadline = Date.now() + 10 * 60_000
  while (Date.now() < deadline) {
    const expiry = await SessionKey.authorizationExpiry(reader, {
      address: state.owner,
      sessionKeyAddress: sessionAddress,
      permission: SessionKey.AddPiecesPermission,
    }).catch(() => 0n) // devnet null rounds: keep polling
    if (expiry > BigInt(Math.floor(Date.now() / 1000))) {
      log(`The chain shows the agent key authorised until ${new Date(Number(expiry) * 1000).toLocaleString()}.`, 'ok')
      return
    }
    await new Promise((resolve) => setTimeout(resolve, 3000))
  }
  throw new Error('Gave up after 10 minutes: the agent key was never authorised.')
}

// ── 5. recover from the wallet ──────────────────────────────────────────────

on('forget', async () => {
  keyspaces.clear()
  state.current = null
  state.dataSet = null
  log('Forgot every key in this tab, the same as a reload.')
})

on('recover', async () => {
  const before = state.signatures
  const { items } = await getClientDataSets(reader, { address: state.owner })
  log(`The chain lists ${items.length} dataset(s) paid for by this wallet.`)
  for (const { dataSetId } of items) {
    const metadata = await getAllDataSetMetadata(reader, { dataSetId: BigInt(dataSetId) })
    const recorded = metadata[Keysmith.KEYSPACE_ID_KEY]
    const recordedCommitment = metadata[Keysmith.COMMITMENT_KEY]
    if (recorded && recordedCommitment) {
      // Checked before signing, so a dataset from a pre-release format costs no prompt.
      if (!/^v1\.[0-9a-f]{32}$/.test(recordedCommitment)) {
        log(`Dataset ${dataSetId}: a pre-release commitment (${recordedCommitment.slice(0, 8)}…), skipped.`, 'dim')
        continue
      }
      try {
        await keysFor(recorded, recordedCommitment)
      } catch (err) {
        log(`Dataset ${dataSetId}: ${err.message}. Not decrypting.`, 'error')
        continue
      }
      // Pick up where step 3 left off, so step 4 works after a reload.
      const { clientDataSetId } = await getDataSet(reader, { dataSetId: BigInt(dataSetId) })
      state.current = { owner: state.owner, keyspace: recorded }
      state.dataSet = { id: BigInt(dataSetId), clientDataSetId }
    }
    for (const piece of await listPiecesOnChain(reader, dataSetId)) {
      const blob = await getPiece(sp.serviceURL, piece.pieceCid)
      let appMetadata
      try {
        ;({ appMetadata } = parseEnvelope(blob))
      } catch {
        log(`Dataset ${dataSetId} · piece ${piece.pieceId}: not encrypted, skipped.`, 'dim')
        continue
      }
      if (appMetadata['foc/v'] !== 1 || !appMetadata['foc/ks']) {
        log(`Dataset ${dataSetId} · piece ${piece.pieceId}: a pre-release envelope (foc/v ${appMetadata['foc/v']}), skipped.`, 'dim')
        continue
      }
      const { kk } = await keysFor(appMetadata['foc/ks'])
      const text = new TextDecoder().decode(await decrypt(blob, Keysmith.keyForEnvelope(kk, appMetadata)))
      log(`Dataset ${dataSetId} · piece ${piece.pieceId} [${appMetadata['foc/scope'] ?? 'no scope'}]: "${text}"`, 'ok')
    }
  }
  log(`Recovered with ${state.signatures - before} new signature(s): one per keyspace not already in the tab.`)
  if (state.dataSet) log(`Continuing with dataset ${state.dataSet.id}: step 4 is ready.`, 'dim')
})

// ── page plumbing ───────────────────────────────────────────────────────────

function log(text, kind = '', href) {
  const line = document.createElement('div')
  line.className = kind
  line.textContent = text
  if (href) {
    const a = Object.assign(document.createElement('a'), { href, target: '_blank', textContent: href })
    line.append(a)
  }
  $('log').append(line)
  line.scrollIntoView({ block: 'nearest' })
}

const prompt = (text) => {
  log(`MetaMask → ${text}`, 'prompt')
  log('No MetaMask window? Click the MetaMask icon in the toolbar: requests queue there, one at a time.', 'dim')
}

function rejected(err) {
  for (let e = err; e; e = e.cause) if (e.code === 4001) return true
  return false
}

function on(id, fn) {
  $(id).addEventListener('click', async () => {
    for (const button of document.querySelectorAll('button')) button.disabled = true
    try {
      await fn()
    } catch (err) {
      console.error(err)
      const detail = err?.details ? ` (${err.details})` : ''
      log(rejected(err) ? 'Rejected in MetaMask. Nothing was signed or sent.' : `Error: ${err?.shortMessage ?? err?.message ?? err}${detail}`, 'error')
    } finally {
      render()
    }
  })
}

function render() {
  $('connect').disabled = state.owner != null
  $('keyspace').disabled = state.owner == null
  $('create').disabled = state.current == null || state.dataSet != null
  $('delegate').disabled = state.dataSet == null
  $('forget').disabled = keyspaces.size === 0
  $('recover').disabled = state.owner == null
}

render()
log(`Devnet ${runId} · SP ${sp.serviceURL}`, 'dim')
