import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

it("keeps npm and JSR entrypoints, versions and dependency mappings aligned", () => {
  const npm = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const jsr = JSON.parse(readFileSync(new URL("../jsr.json", import.meta.url), "utf8"));
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
