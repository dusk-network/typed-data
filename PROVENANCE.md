# Authorship and extraction provenance

The protocol specification, typed-data reference implementation, vector generator/corpus and BLS verification were originally authored by **ichbindas**, using the Git identity `ichbindas <54631150+ichbindas@users.noreply.github.com>`, in [Connect PR #35](https://github.com/dusk-network/connect/pull/35). The Wallet companion is [PR #101](https://github.com/dusk-network/wallet/pull/101).

The initial extraction imported the relevant history from Connect commit `bbbbd8d8b29de2c029fe6c5a07c2022b686abe1f`, not a new flattened copy attributed to the extractor. Selected paths: `LICENSE`, `src/bytes.ts`, `src/typed-data/`, `src/bls/`, `docs/typed-data-v1.md`, `scripts/generate-typed-data-vectors.ts`, and `vectors/typed-data-v1/`.

Git's native `fast-export`/`fast-import` path filtering changes commit IDs because unrelated files/history are excluded. **Authors, author dates, committers, committer dates and commit messages were preserved and compared exactly for all nine imported commits.** The initial imported tree was byte-identical to the selected original tree. Original Connect and Wallet PR histories were not rewritten. The Dusk Network MIT license remains unchanged.

| Original Connect commit | Imported commit | Original author / scope |
|---|---|---|
| `38a2f8918013db3e2f2662a9af699b9780eab9fb` | `7021f9531966cb776d18c29f84cc29c9bb6042be` | Hein Dauven — original license/byte helpers |
| `9cfc2f4d6ffad8119793c301aa283d8f3b423358` | `616320c31dccc393353aae31d344936fc965cea9` | Hein Dauven — byte-helper API documentation |
| `9bdd1ff4710b3ebcbebb1e9936ab24277588a790` | `542c7a0af6bf3ffa899d98de276fa377f0972acb` | ichbindas — specification |
| `a9e9cbd49f0f6974b3768477981cec268da36ff8` | `9c77e19df67be6eef98a9ecf670341d305cf6822` | ichbindas — reference implementation |
| `4defdee68cf50cc31fffd12ec7d6f760fe87aed5` | `f7d3df9893d941488be7af3d005190d48aa34b64` | ichbindas — generator and frozen corpus |
| `fe69c1d6be5c9fb0e5471e0f47056d9f41f30b1f` | `f43e9af13e1f264cc41d2877fc3302493dd13d8a` | ichbindas — BLS verification |
| `5eb375d032cd4a9ee24496ff4f80cdedf6c955b6` | `588db73ce72704e516cb55758d17a84fb1073767` | ichbindas — signed-message vector pinning |
| `72ac9cd2cedab7e66427520234bd9f43fb4f5c50` | `5a257cd548f1b59f08fad145290e8defbb64e16f` | Hein Dauven — validation/package corrections |
| `bbbbd8d8b29de2c029fe6c5a07c2022b686abe1f` | `5e960d2129ccab1e65870b4a87c9297fb7547549` | Hein Dauven — focused simplification |

ichbindas's five original feature commits retain their 2026-08-29/30 author dates. New extraction/packaging changes are separate commits authored by Hein Dauven. Shared-package tests additionally retain coverage for the Wallet's empty-types, large-array and struct-count boundaries; those are not a second encoder implementation.

The original 35 typed-data JSON vectors retain their exact bytes from that Connect head. Moving their ownership does not independently validate their encoding: the v1 specification remains draft and requires independent review before freezing.

## Later ichbindas follow-ups

The eight subsequent Connect commits through `748ae84be8d09e7ecda487bd25695538d6616e9a` are imported below. Unlike the initial filtered import, these use `git cherry-pick -x`: **ichbindas's author identity and original author dates are retained**, and each commit links its original SHA. Hein Dauven is the committer of these transplants; their committer dates reflect the import, not the original commits. His separate adaptation commit updates the existing builder export assertion, adds error-order regressions and a runnable native comparison, and records package/provenance documentation. No contributor history is rewritten.

| Original Connect commit | Library commit | Scope |
|---|---|---|
| `6b0f9df834b11245552f21036a23339006831aba` | `95f49264eb3e1ff380daba63b5d65ee00c6a7f3b` | V2-only scheme specification |
| `1a20cd4a989e4f68f46bd9b8ef74b8694f181a76` | `2f0940e8debd86b31bdb95247d5f4c94ee6e2706` | Validation scope and error reporting |
| `fc5100ced29df7120bef3cda520c68efda39e583` | `59adae9ea3f3d2420ece02406bf05bfa44350f48` | Hash/debug error-order consistency |
| `9060a8cf332eed061432a44025d052f241c0b203` | `1b3a0f0f445a670713e02c741c897fae09c4d6c7` | Unreferenced-type vector |
| `55b5dae7c3d45654ae8eb8551a894153c9877ff4` | `d043e242fde01428c29236a08bf8dc6a1700514a` | V2 export/DST tests |
| `7b0d391f2e597c63b9dc2a3ebdaf86e41c84e950` | `c20140f7a223c59f40d3ea65ab1b09bea910f5ca` | BLS corpus, generator and native Rust emitter |
| `7c1929ae5cc5ff10a963a615f553b2bd1148c5e6` | `3af197df8dbb6cae5fb1fc8ee486c59a8f50bf2f` | Exact Noble dependency pins |
| `748ae84be8d09e7ecda487bd25695538d6616e9a` | `b7de57a65fbb96b6c3b9827a92d3d4a70c6a15ac` | Follow-up changelog entries |

The only cherry-pick conflict was the differently structured changelog; the four new follow-up entries were retained without copying unrelated Connect release history. The shared hasher matches the new Connect source exactly. The corpus now has 14 accept / 22 reject typed-data vectors and five BLS vectors, all byte-identical to that source snapshot. The native emitter's derivation is transcribed from wallet-core; its BLS crate and transitive versions are pinned by its Cargo lockfile. Native agreement does not constitute independent typed-data encoding approval.
