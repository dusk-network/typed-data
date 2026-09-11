// Compare every frozen BLS vector with the locked native Rust emitter.
// Seeds and secret scalars in this corpus are public test data, never wallet keys.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const directory = new URL("../../vectors/bls-v1/", import.meta.url);
const names = readdirSync(directory).filter(name => name.endsWith(".json")).sort();
assert.ok(names.length > 0, "BLS corpus must not be empty");
const native = JSON.parse(execFileSync("cargo", [
  "run", "--quiet", "--locked", "--manifest-path",
  fileURLToPath(new URL("Cargo.toml", import.meta.url)),
], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }));
assert.deepEqual(Object.keys(native).sort(), names.map(name => name.slice(0, -5)));
for (const name of names) {
  const vector = JSON.parse(readFileSync(new URL(name, directory), "utf8"));
  assert.deepEqual(native[name.slice(0, -5)], vector.expected, name);
}
console.log(`PASS: all ${names.length} frozen BLS vectors match the locked Rust emitter (key, public key, tagged message and signature).`);
