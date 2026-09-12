import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { expect, it } from "vitest";
import * as typedData from "./typed-data/index.js";
import * as policy from "./policy/index.js";
import { checkPolicyLimits } from "./typed-data/hash.js";

const npm = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const jsr = JSON.parse(readFileSync(new URL("../jsr.json", import.meta.url), "utf8"));

it("keeps npm and JSR entrypoints, versions and dependency mappings aligned", () => {
  expect(Object.keys(jsr.exports).sort()).toEqual([".", "./bls", "./policy"]);
  expect(jsr.name).toBe(npm.name);
  expect(jsr.version).toBe(npm.version);
  for (const [name, source] of Object.entries(jsr.exports) as [string, string][]) {
    expect(npm.exports[name]).toEqual({
      types: source.replace("./src/", "./dist/").replace(/\.ts$/, ".d.ts"),
      import: source.replace("./src/", "./dist/").replace(/\.ts$/, ".js"),
    });
  }
  for (const [name, version] of Object.entries(npm.dependencies)) {
    expect(jsr.imports[name]).toBe(`npm:${name}@${version}`);
  }
});

it("offers resource limits only through the opt-in policy entrypoint", () => {
  expect(typedData).not.toHaveProperty("checkPolicyLimits");
  expect({ ...policy }).toEqual({ checkPolicyLimits });
});

it("exports the BLS corpus without escaping the package export map", () => {
  expect(npm.exports["./vectors/bls-signing/*"]).toBe("./vectors/bls-signing/*");
  const require = createRequire(import.meta.url);
  const directory = new URL("../vectors/bls-signing/", import.meta.url);
  const names = readdirSync(directory).filter(name => name.endsWith(".json"));
  expect(names).toHaveLength(5);
  for (const name of names) {
    const resolved = require.resolve(`@dusk/typed-data/vectors/bls-signing/${name}`);
    expect(readFileSync(resolved, "utf8")).toBe(readFileSync(new URL(name, directory), "utf8"));
  }
});
