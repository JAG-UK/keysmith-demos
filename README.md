# Keysmith demos

Six small scripts and two browser pages against a local [`foc-devnet`](https://github.com/FilOzone/foc-devnet).
Real `createDataSet`, real `addPieces`, real `GET` from Curio. Every key in them is
derived from one wallet signature; nothing is stored by this layer and nothing but a
16-byte commitment goes on chain.

They exist to show a maintainer **where the layering cuts**:

| Layer | Who | In these demos |
| --- | --- | --- |
| key source | **Keysmith, proposed** | [`lib/keys.mjs`](lib/keys.mjs) — `node:crypto` and `cborg` only |
| envelope | FEE | [`filecoin-encryption-envelope`](https://www.npmjs.com/package/filecoin-encryption-envelope) 0.1.0, via [`lib/fee.mjs`](lib/fee.mjs) — takes a key and bytes, knows nothing else |
| storage | Synapse / FWSS / Curio | [`lib/store.mjs`](lib/store.mjs) — moves opaque bytes |

The library these demos argue for is proposed as `@filoz/keysmith` in
[FilOzone/synapse-sdk#983](https://github.com/FilOzone/synapse-sdk/pull/983). That
package is TypeScript and browser-safe; `lib/keys.mjs` here is the same construction in
plain Node, kept readable for a walkthrough — and kept **byte-compatible**: the same
signature yields the same keys in both, and a grant made by either opens with the other.
`lib/keys.test.mjs` checks the construction offline in 55 checks, including the package's
pinned test vectors when a synapse-sdk checkout is alongside.

## Prerequisites

1. **A devnet.** Clone [`foc-devnet`](https://github.com/FilOzone/foc-devnet), then
   `cargo run -- start` (~8 min, needs Docker). The demos read
   `~/.foc-devnet/state/latest/devnet-info.json`, or `$DEVNET_INFO_PATH`.

FEE needs no setup: it is the published
[`filecoin-encryption-envelope`](https://www.npmjs.com/package/filecoin-encryption-envelope)
0.1.0, installed with everything else. FEE is streaming;
[`lib/fee.mjs`](lib/fee.mjs) runs whole pieces through it so the demos read as steps.

## Run

```bash
pnpm install
```

```bash
for d in 0*.mjs; do echo "── $d"; node "$d" || break; done
```

Run them in order: 1 creates the dataset, 2–4 add pieces to it, 5–6 read them back.
State passes through `out/state.json`, and grants are written to `out/` as `.cbor`
files, about 200 bytes each; delete `out/` to start again. Demo 6 reads nothing from
`out/` by design.

## In the browser, with MetaMask

[`web/`](web/) is the same story from a browser wallet: connect, start a keyspace, create a
dataset, delegate to an agent, and recover from nothing. It imports `@filoz/keysmith`
itself, not `lib/keys.mjs`, and announces every MetaMask prompt in its log before it
appears.

1. **The package source.** The page loads `@filoz/keysmith` from a synapse-sdk checkout on
   `feat/keysmith`, with its dependencies installed. It looks in
   `../../synapse-sdk/packages/keysmith`; set `KEYSMITH_DIR` if yours is elsewhere.
2. **A funded account in MetaMask.** Import a devnet user's key (MetaMask → Add account →
   Import account). `USER_2` is funded and has never used storage, so it shows the whole
   first-time flow. Print its key with:

   ```bash
   jq -r '.info.users[1].private_key_hex' ~/.foc-devnet/state/latest/devnet-info.json
   ```

3. **Run it**, then open <http://localhost:5780> in the browser that has MetaMask:

   ```bash
   pnpm web
   ```

What a first-time wallet is asked for:

| Step | MetaMask prompts |
| --- | --- |
| Connect | connect; add and switch to the devnet network |
| Start a keyspace | 2 identical signatures the first time this browser sees the wallet, then 1 |
| Create a dataset | first time only: USDFC allowance, deposit, approve Warm Storage (3 transactions); then 2 signatures (create dataset, add pieces), which the SP submits |
| Delegate to an agent | in the Filecoin Pay console: connect, approve the key, 1 transaction; the agent's own write costs none |
| Recover | 1 signature per keyspace |

Step 4 hands you to the **Filecoin Pay console** to authorise the agent's key, through
the same pairing link `filecoin-pin session create --console` uses, and waits until the
chain shows the key. That needs the console running locally against the devnet, from
the `feat/devnet` branch of [JAG-UK/filecoin-pay-explorer](https://github.com/JAG-UK/filecoin-pay-explorer),
on port 3780:

```bash
cd ../../filecoin-pay-explorer/apps/explorer && FOC_DEVNET=1 \
  NEXT_PUBLIC_SUBGRAPH_URL_MAINNET=https://no-subgraph.invalid \
  NEXT_PUBLIC_SUBGRAPH_URL_CALIBRATION=https://no-subgraph.invalid \
  pnpm exec next dev -p 3780
```

Untick the step 4 checkbox to authorise the key from this page instead.

Reload the page to forget every key, then Connect and Recover. Import `USER_1` instead
and Recover also opens the pieces the Node demos wrote: the same wallet derives the same
keys in the package and in `lib/keys.mjs`.

The page serves `devnet-info.json` to itself without the `users` section, so no devnet
private key reaches the browser, and proxies `/rpc/v1` to Lotus, which sends no CORS
headers. Restart `pnpm web` after restarting the devnet.

## The demo app

[`app/`](app/) is the whole story in one page, on devnet, calibration or mainnet:

1. **Owner.** Start a keyspace from your wallet, encrypt a first piece, and hand it to
   `synapse.storage.upload()` with the keyspace and its commitment as dataset metadata.
   Reload, then Recover: one signature per keyspace rebuilds every key from the chain.
2. **Session keys.** Authorise agents in SessionKeyRegistry, in the same shape as the
   Filecoin Pay console (`login`, `revoke`, live status), and share each one encryption
   grants: `scope:shared` for all of them, and `scope:agents/<name>` for each. Agents
   then upload through Synapse as their session keys, with no wallet prompt.
3. **Who can read what.** Every reader against every piece of the keyspace: green is a
   real decryption of the ciphertext Synapse downloaded, red is Keysmith's reason why not.
4. **Inspector.** Drop in a piece or a grant (file, pasted hex or base64, or a CID) to see
   its bytes decoded field by field, who can open it, and the derivation path.

```bash
pnpm app
```

Then open <http://localhost:5790> in a browser with your wallet. `pnpm app:check`
type-checks it. `pnpm app:build` builds a static site into `dist-app/` that you can host
anywhere; built that way it offers calibration and mainnet only, since devnet needs the
dev server's proxy.

### Networks

| Network | Tokens |
| --- | --- |
| Devnet | Import a devnet user's key into your wallet (see above) |
| Calibration | tFIL for gas and USDFC for storage, from the [calibration faucets](https://docs.filecoin.io/networks/calibration) |
| Mainnet | Real FIL and USDFC: everything costs money |

The app never chooses or remembers a storage provider. Synapse picks them and keeps
copies, and repair can move pieces between providers and datasets without telling
anyone. So every write passes the same dataset metadata (`foc/ks`, `foc/kc`) and Synapse
adds to whichever datasets match. Every read lists the keyspace's pieces from the chain
and fetches each one by piece CID with `synapse.storage.download()`. On public networks,
Recover scans only datasets that record a keyspace, so it never downloads other apps' data.

Uploads are confirmed by the chain. Curio batches piece additions, and its add-pieces status
endpoint can answer 404 or "not yet" for minutes after the transaction has landed, which
`upload()` waits on. Once Synapse has submitted the add-pieces transactions, the app takes
their receipts as the confirmation ([`app/src/storage.ts`](app/src/storage.ts)).

Agents check their own authorization with an account-less read of SessionKeyRegistry.
`sessionKey.syncExpirations()` reads as the session key, and Lotus refuses calls from an
address it has never seen, so a fresh key would read as unauthorized.

Calibration's providers currently advertise a 1 MiB minimum piece size, and Synapse does
not enforce it. If a provider refuses a small piece, write a longer one.

### What a first run costs

| Step | Wallet prompts |
| --- | --- |
| Connect | connect; add or switch network |
| Start a keyspace | 2 identical signatures the first time this browser sees the wallet, then 1 |
| Store the first piece | first time only: USDFC allowance, deposit, approve Warm Storage (3 transactions); then Synapse's signatures to create the datasets and add the piece, for each copy (6 on devnet, with two copies), which the providers submit |
| Each session key | 1 transaction (`login`); its encryption grants cost none |
| Each agent write | none: the agent signs with its session key |
| Revoke | 1 transaction |
| Recover | 1 signature per keyspace |

### Wallets

Keysmith needs a wallet that signs EIP-712 with a plain secp256k1 key, and signs the same
message the same way every time (RFC 6979). The app checks both, and explains a refusal in
its activity log.

| Wallet | Expected |
| --- | --- |
| MetaMask (extension) | Works: tested on devnet |
| MetaMask with a Ledger or Trezor | Should work: hardware wallets sign deterministically |
| Rabby, Coinbase Wallet (extension, not smart wallet), Frame | Should work; not yet tested |
| Safe, Coinbase Smart Wallet, ERC-4337 and passkey accounts | Refused: their signatures are not plain ECDSA, so there is no key to derive from |
| Embedded and MPC wallets that randomise signatures | Refused: the first keyspace's two signatures differ |

Browser wallets connect through EIP-6963, so each installed wallet appears by name.
WalletConnect, for mobile wallets, is not included: it needs a project id.

## Verbose tracing

`FOC_VERBOSE=1` (or `--verbose`) adds a `│`-prefixed trace beside the normal output,
which is otherwise unchanged:

```bash
FOC_VERBOSE=1 node 05-curio-get.mjs
```

It prints what is actually on the wire and in the bytes:

- **The envelope**, with the CDDL it conforms to: CBOR tag, protected vs unprotected
  headers with their COSE labels named, the whole structure in RFC 8949 diagnostic
  notation, and the `Enc_structure` AAD that binds the protected header to the ciphertext.
- **The chunk table** — for each chunk, its plaintext range, its slice of the blob, and
  its derived nonce (`base[0..6] ‖ uint32be(index) ‖ last_flag`). This is what a range
  read seeks through.
- **Key identification**: what the envelope's `app_metadata` says, which node the caller
  holds, and the resulting walk — `walk: KK ──"agent-memory"──▶ RK ──salt──▶ PK`.
- **Every HKDF step**, with its IKM, its exact `info` string and its output, so a reader
  can recompute any key by hand.
- **Unwrapping**: the ephemeral public key, the ECDH shared secret, the KEK, the
  descriptor as deterministic CBOR used as AAD, the GCM nonce and the wrapped key.
- **The EIP-712 message**, the 65-byte signature, and the 64 bytes of it that become key
  material once `s` is normalised and `v` dropped.
- **Every HTTP call to the SP and every `eth_call`**, with arguments and results.

Demo 4 under `--verbose` is the one that settles arguments: the auditor derives a piece
key from the wrong scope key and GCM rejects it, with both keys on screen.

## What each one shows

1. **`01-create-dataset.mjs` — where the key comes from.** The payer mints a random
   **keyspace**, signs one EIP-712 `KeyspaceKey` message (twice, compared — D3a), and
   derives `KK`. The FWSS `clientDataSetId` is picked separately and is a storage concern
   only: no key depends on it, so the first piece is still encrypted before the dataset
   exists. `foc/ks` and `foc/kc` ride into the `createDataSet` call that was happening anyway.
2. **`02-session-key-write.mjs` — delegated writes.** A session key is authorised on
   chain for `AddPieces` only, and is handed `KK` wrapped to itself (D2), as a CBOR grant
   kept beside its key in `out/agent-credentials.json`. It unwraps,
   derives a piece key, encrypts and calls `addPieces` — all without the payer's wallet.
   The wrapped key ships *with* the session key, so no new state exists anywhere (O1).
3. **`03-share-dataset-read.mjs` — sharing the whole keyspace.** One wrap of `KK` to the
   recipient's public key, delivered out of band as `out/grant-dataset.cbor`. No chain write, no piece rewritten. The
   recipient reads every piece, including ones written later.
4. **`04-share-scope-read.mjs` — sharing by scope, and by piece.**
   `RK = HKDF(KK, "foc/acl/role/v1" ‖ name)`: the label predates the name "scope", and
   changing it would change every key. Pieces are labelled `agent-memory` and
   `super-secret`; an agent is granted `agent-memory` and reads it, while `super-secret`
   fails with an `AuthenticationError` in the same loop. Sibling scopes are unrelated; a
   scope opens only itself and the scopes beneath it.
   Then the payer shares **one** `super-secret` piece with an auditor, as a `piece:<salt>`
   grant carrying the piece's CID as a locator: the auditor fetches and reads that piece,
   is refused the other, and is refused a write.
5. **`05-curio-get.mjs` — retrieval is unchanged.** One `fetch()` at
   `http://localhost:5711/piece/<cid>`, no auth and no chain call. Anyone can read the
   envelope; only a key holder reads the content.
6. **`06-recover-from-nothing.mjs` — the wallet is enough, wherever copies ended up.**
   Walks every dataset the payer funds and opens every piece by the keyspace **its envelope
   names**, not the dataset it was found in — so copies that replication or repair put
   elsewhere open the same way. One signature per distinct keyspace; `foc/kc` is checked
   wherever a dataset recorded it.

## Honest notes

- **FEE is `filecoin-encryption-envelope` 0.1.0**, the published package. Every header,
  Keysmith's `app_metadata` labels included, is in the **protected** header, so the content
  tags authenticate the labels: a tampered `foc/scope` or `foc/salt` fails loudly. FEE hands
  the labels to a key resolver before they are authenticated, which is why Keysmith checks
  them as strictly as any input.
- **The scope label travels in `app_metadata` in clear** — a reader needs it to derive.
  The bytes stay secret, the label does not; for access labels that leaks classification,
  so prefer opaque scope ids with display names held by the app.
- **Wrapping uses secp256k1 ECDH**, which is what D2 implies: session keys and wallets
  are secp256k1, so no separate published encryption key is needed. Hardware and contract
  wallets can't do ECDH — those need the signature-derived X25519 key, still open.
- **We confirm piece additions against PDPVerifier, not the SP status endpoint.**
  synapse-core polls `/pdp/data-sets/{id}/pieces/added/{hash}`. Curio batches piece
  additions, so that endpoint answers 404 ("Piece addition not found for given
  transaction") or "not yet" long after the transaction has landed, and synapse-core gives
  up. The pieces are on chain either way.
- **A dataset can mix encrypted and plaintext pieces.** Demo 6 skips anything that isn't a
  FEE envelope.
