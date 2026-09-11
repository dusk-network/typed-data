/** Hex decoding retained for compatibility with the existing BLS verifier API. */

/** Return true when a value is a valid even-length hex string. */
export function isHexString(s: unknown): s is string {
  return typeof s === "string" && /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0;
}

/** Decode a hex string, with or without `0x`, into bytes. */
export function hexToBytes(hex: string): Uint8Array {
  let s = String(hex || "").trim();
  if (s.startsWith("0x") || s.startsWith("0X")) s = s.slice(2);
  if (s === "") return new Uint8Array();
  if (!isHexString(s)) throw new Error("Invalid hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
