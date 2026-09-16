// Run after building, outside Vitest: Node loads the actual dist-backed export.
// The source encoder uses native TypeScript support, as the vector generator does.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import * as source from "../src/typed-data/hash.ts";
import * as built from "@dusk/typed-data";

const root = new URL("../vectors/typed-data-v1/", import.meta.url);
for (const folder of ["", "reject/"]) {
  const directory = new URL(folder, root);
  const names = readdirSync(directory).filter(name => name.endsWith(".json")).sort();
  assert.ok(names.length > 0, `${folder || "accept/"} corpus must not be empty`);
  for (const name of names) {
    const vector = JSON.parse(readFileSync(new URL(name, directory), "utf8"));
    for (const [label, api] of [["source", source], ["built", built]]) {
      const context = `${label}: ${folder}${name}`;
      const input = () => structuredClone(vector.input);
      if (folder) {
        for (const method of ["hashTypedData", "hashTypedDataHex", "hashTypedDataDebug"]) {
          assert.throws(() => api[method](input()),
            error => error instanceof api.TypedDataError && error.code === vector.error,
            `${context}: ${method} must reject with ${vector.error}`);
        }
      } else {
        assert.equal(api.hashTypedDataHex(input()), vector.digestHex, context);
        assert.equal(`0x${Buffer.from(api.hashTypedData(input()).digest).toString("hex")}`,
          vector.digestHex, context);
        const { description, input: _, signedMessageHex, ...expected } = vector;
        expected.typeHashes = Object.assign(Object.create(null), expected.typeHashes);
        assert.deepEqual(api.hashTypedDataDebug(input()), expected, context);
      }
    }
  }
  console.log(`PASS: source and built entrypoint match all ${names.length} frozen ${folder ? "reject vectors (three hash APIs and error codes)" : "accept vectors (digests and intermediates)"}`);
}
