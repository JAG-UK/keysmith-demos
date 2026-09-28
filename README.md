# Keysmith demos

Six small scripts against a local [`foc-devnet`](https://github.com/FilOzone/foc-devnet).
Real `createDataSet`, real `addPieces`, real `GET` from Curio. Every key in them is
derived from one wallet signature; nothing is stored by this layer and nothing but a
16-byte commitment goes on chain.

They exist to show a maintainer **where the layering cuts**:

| Layer | Who | In these demos |
|---|---|---|
| key source | **Keysmith, proposed** | [`lib/keys.mjs`](lib/keys.mjs) — 150 lines, `node:crypto` only |
| envelope | FEE | `foc-encryption` — takes a key and bytes, knows nothing else |
| storage | Synapse / FWSS / Curio | [`lib/store.mjs`](lib/store.mjs) — moves opaque bytes |

The library these demos argue for is proposed as `@filoz/keysmith` in
[FilOzone/synapse-sdk#983](https://github.com/FilOzone/synapse-sdk/pull/983). That
package is TypeScript and browser-safe; `lib/keys.mjs` here is the same construction in
plain Node, kept readable for a walkthrough — and kept **byte-compatible**: the same
signature yields the same keys in both, and a grant made by either opens with the other.
`lib/keys.test.mjs` checks the construction offline in 25 assertions.

## Prerequisites

1. **A devnet.** Clone [`foc-devnet`](https://github.com/FilOzone/foc-devnet), then
   `cargo run -- start` (~8 min, needs Docker). The demos read
   `~/.foc-devnet/state/latest/devnet-info.json`, or `$DEVNET_INFO_PATH`.
2. **The FEE library, as a sibling checkout.** It is not published to npm, so
   `package.json` refers to it by path:

   ```text
   work/
   ├── keysmith-demos/        ← this repo
   └── foc-encryption-demo/   ← https://github.com/Kubuxu/foc-encryption-demo, at 6d9f575
   ```

   ```bash
   git clone https://github.com/Kubuxu/foc-encryption-demo.git
   cd foc-encryption-demo && git checkout 6d9f575 && pnpm install && pnpm -r build
   ```

   Adjust the `foc-encryption` path in `package.json` if you put it elsewhere.

## Run

```bash
pnpm install
```

```bash
for d in 0*.mjs; do echo "── $d"; node "$d" || break; done
```

Run them in order: 1 creates the dataset, 2–4 add pieces to it, 5–6 read them back.
State passes through `out/state.json`; delete `out/` to start again. Demo 6 reads
nothing from `out/` by design.

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
  holds, and the resulting walk — `DK ──scope "invoices"──▶ SK ──salt──▶ PK`.
- **Every HKDF step**, with its IKM, its exact `info` string and its output, so a reader
  can recompute any key by hand.
- **Unwrapping**: the ephemeral public key, the ECDH shared secret, the KEK, the
  descriptor JSON used as AAD, the GCM nonce and the wrapped key.
- **The EIP-712 message**, the 65-byte signature, and the 64 bytes of it that become key
  material once `s` is normalised and `v` dropped.
- **Every HTTP call to the SP and every `eth_call`**, with arguments and results.

Demo 4 under `--verbose` is the one that settles arguments: the auditor derives a piece
key from the wrong scope key and GCM rejects it, with both keys on screen.

## What each one shows

1. **`01-create-dataset.mjs` — where the key comes from.** The payer picks
   `clientDataSetId`, signs one EIP-712 `DatasetKey` message (twice, compared — D3a),
   and derives `DK`. The first piece is encrypted *before* the dataset exists on chain,
   which is the point of keying on `clientDataSetId` rather than the chain-assigned id.
   `foc/kc` rides into the `createDataSet` call that was happening anyway (D3b).
2. **`02-session-key-write.mjs` — delegated writes.** A session key is authorised on
   chain for `AddPieces` only, and is handed `DK` wrapped to itself (D2). It unwraps,
   derives a piece key, encrypts and calls `addPieces` — all without the payer's wallet.
   The wrapped key ships *with* the session key, so no new state exists anywhere (O1).
3. **`03-share-dataset-read.mjs` — sharing the whole dataset.** One wrap of `DK` to the
   recipient's public key, ~520 bytes, delivered out of band. No chain write, no piece
   rewritten. The recipient reads every piece, including ones written later.
4. **`04-share-scope-read.mjs` — sharing a subset.** `SK = HKDF(DK, "scope" ‖ name)`.
   The auditor gets `invoices` and can read it; `payroll` fails with an
   `AuthenticationError` in the same loop.
5. **`05-curio-get.mjs` — retrieval is unchanged.** One `fetch()` at
   `http://localhost:5711/piece/<cid>`, no auth and no chain call. Anyone can read the
   envelope; only a key holder reads the content.
6. **`06-recover-from-nothing.mjs` — the wallet is enough.** Lists the payer's datasets
   from FWSS, re-signs, checks `foc/kc` *before* decrypting anything, lists pieces from
   PDPVerifier, GETs each and decrypts — including the agent's piece and both scopes.

## Honest notes

- **The FEE library here is `foc-encryption` (Kubuxu/Peeja @6d9f575), not
  [synapse-sdk#967](https://github.com/FilOzone/synapse-sdk/pull/967).** #967 currently
  contains constants, nonce and chunk-layout only — no `encrypt`/`decrypt`/`wrapKey` yet.
  The demos use the same COSE wire format and should port when #967 lands. One difference
  matters: #967 puts `app_metadata` in the **protected** header; `foc-encryption` leaves it
  unprotected. Nothing here depends on it, because a tampered `foc/salt` yields a wrong key
  and a loud AEAD failure.
- **The scope name travels in `app_metadata` in clear** — a reader needs it to derive.
  The bytes stay secret, the label does not. Sealing labels per level is possible (see
  [`../../keysmith`](../../keysmith/keysmith.md)) and costs an ECDH per level.
- **Wrapping uses secp256k1 ECDH**, which is what D2 implies: session keys and wallets
  are secp256k1, so no separate published encryption key is needed. Hardware and contract
  wallets can't do ECDH — those need the signature-derived X25519 key, still open.
- **We confirm piece additions against PDPVerifier, not the SP status endpoint.**
  `synapse-core@0.9.1` polls `/pdp/data-sets/{id}/pieces/added/{hash}`, which this devnet's
  Curio build does not serve ("Piece addition not found for given transaction"). The SDK's
  own `storage.upload()` fails identically here, so it is version drift, not these demos —
  the pieces land on chain correctly either way.
- **A dataset can mix encrypted and plaintext pieces.** Demo 6 skips anything that isn't a
  FEE envelope.
