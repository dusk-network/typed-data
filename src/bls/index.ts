/**
 * Dusk BLS12-381 short-signature verification for typed-data v1 (opt-in).
 *
 * This entrypoint is not part of the root `@dusk/typed-data` export - import it
 * explicitly from `@dusk/typed-data/bls` when a verifier (a relayer, a dApp
 * backend, tests) needs to check a Dusk typed-data v1 signature.
 *
 * @example
 * ```ts
 * import { verifyTypedDataSignature } from "@dusk/typed-data/bls";
 * ```
 *
 * @module
 */

export type { HashTypedDataInput } from "../typed-data/hash.js";
export { BLS_SIGN_DST, TYPED_DATA_SIG_TAG, buildTypedDataSignedMessage, verifyTypedDataSignature, verifyBlsDigest } from "./sig.js";
