# Authorship and extraction provenance

The protocol specification, typed-data reference implementation, vector generator/corpus and BLS verification were originally authored by **ichbindas**, using the Git identity `ichbindas <54631150+ichbindas@users.noreply.github.com>`, in [Connect PR #35](https://github.com/dusk-network/connect/pull/35). The Wallet companion is [PR #101](https://github.com/dusk-network/wallet/pull/101).

This repository imports the relevant history from Connect commit `bbbbd8d8b29de2c029fe6c5a07c2022b686abe1f`, not a new flattened copy attributed to the extractor. Selected paths: `LICENSE`, `src/bytes.ts`, `src/typed-data/`, `src/bls/`, `docs/typed-data-v1.md`, `scripts/generate-typed-data-vectors.ts`, and `vectors/typed-data-v1/`.

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

The 35 JSON vectors retain their exact bytes from the above Connect head. Moving their ownership does not independently validate their encoding: the v1 specification remains draft and requires independent review before freezing.
