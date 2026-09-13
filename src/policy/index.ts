/**
 * Opt-in signer resource policy (spec §11), separate from digest validity.
 * Verifiers must accept otherwise-valid inputs within the floor, but may
 * decline larger requests at their transport boundary.
 *
 * @module
 */
export { checkPolicyLimits } from "../typed-data/hash.js";
