import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToHex } from "@noble/hashes/utils";
import { hashTypedData } from "@dusk/typed-data";
import { BLS_SIGN_DST, buildTypedDataSignedMessage, verifyTypedDataSignature } from "@dusk/typed-data/bls";
import { initApprovalStore, issueApproval, acceptApproval } from "../examples/approve-document.mjs";

const hex = bytes => `0x${bytesToHex(bytes)}`;
const publicKey = key => hex(bls12_381.getPublicKeyForShortSignatures(key));
const documentHash = `0x${"ab".repeat(32)}`;
// PUBLIC TEST KEYS ONLY. These are not real wallets; never fund them.
function sign(input, key = 1n) {
  return {
    origin: input.origin,
    publicKeyHex: publicKey(key),
    signature: hex(bls12_381.signShortSignature(
      buildTypedDataSignedMessage(hashTypedData(input).digest), key, { DST: BLS_SIGN_DST },
    )),
  };
}

// Instrument the real SELECT only to force a stale snapshot. No fake SQL rows,
// hasher or signature verifier, and no test hook in the application example.
function afterSelect(db, callback) {
  const prepare = db.prepare.bind(db);
  db.prepare = sql => {
    const statement = prepare(sql);
    if (sql.startsWith("SELECT * FROM approval_requests")) {
      const get = statement.get.bind(statement);
      statement.get = (...args) => {
        const row = get(...args);
        assert.ok(row, "the race must start with a real pending row");
        callback(row);
        return row;
      };
    }
    return statement;
  };
  return () => { db.prepare = prepare; };
}

if (!isMainThread) {
  const db = new DatabaseSync(workerData.path, { timeout: 5000 });
  const gate = new Int32Array(workerData.gate);
  let result;
  try {
    afterSelect(db, () => {
      Atomics.add(gate, 0, 1);
      Atomics.notify(gate, 0);
      while (Atomics.load(gate, 0) < 2) {
        assert.notEqual(Atomics.wait(gate, 0, 1, 5000), "timed-out", "both workers must read before either updates");
      }
    });
    acceptApproval(db, workerData.nonce, workerData.response);
    result = { ok: true };
  } catch (error) {
    result = { ok: false, error: error.message };
  } finally {
    db.close();
  }
  parentPort.postMessage(result);
} else {
  const directory = mkdtempSync(join(tmpdir(), "typed-data-approval-"));
  const path = join(directory, "approvals.sqlite");
  const db = new DatabaseSync(path, { timeout: 5000 });
  let clock = Math.floor(Date.now() / 1000);
  let checks = 0;
  const workers = [];
  db.function("unixepoch", () => clock);
  initApprovalStore(db);
  const fresh = () => {
    clock = Math.floor(Date.now() / 1000);
    return issueApproval(db, documentHash, publicKey(1n));
  };
  const pending = nonce => assert.equal(db.prepare(
    "SELECT approved_at FROM approval_requests WHERE nonce = ?"
  ).get(nonce).approved_at, null);
  const passed = name => { checks++; console.log(`PASS ${name}`); };

  try {
    for (const [name, change] of [
      ["document", input => { input.message.documentHash = `0x${"cd".repeat(32)}`; }],
      ["nonce", input => { input.message.nonce = `0x${"00".repeat(32)}`; }],
      ["expiry", input => { input.message.expiresAt = String(Number(input.message.expiresAt) + 1); }],
      ["domain name", input => { input.domain.name = "Another application"; }],
      ["domain version", input => { input.domain.version = "2"; }],
      ["contract", input => { input.domain.verifyingContract = `0x${"11".repeat(32)}`; }],
      ["chain", input => { input.domain.chainId = "dusk:1"; }],
      ["origin", input => { input.origin = "https://other.example"; }],
      ["primary type", input => {
        input.types.OtherApproval = input.types.DocumentApproval;
        input.primaryType = "OtherApproval";
      }],
      ["schema", input => {
        input.types.DocumentApproval[0].name = "otherHash";
        input.message.otherHash = input.message.documentHash;
        delete input.message.documentHash;
      }],
    ]) {
      const input = fresh();
      const changed = structuredClone(input);
      change(changed);
      const response = sign(changed);
      assert.equal(verifyTypedDataSignature(changed, response.signature, publicKey(1n), {
        chainId: changed.domain.chainId, origin: changed.origin,
      }).ok, true, `${name}: the negative control must be a genuinely valid signature for a different request`);
      assert.throws(() => acceptApproval(db, input.message.nonce, response), /E_SIG_INVALID|E_ORIGIN_MISMATCH/);
      pending(input.message.nonce);
      assert.equal(acceptApproval(db, input.message.nonce, sign(input)).document_hash, documentHash);
      passed(`rejects changed ${name}; original request remains approvable`);
    }

    assert.throws(() => issueApproval(db, "0x12", publicKey(1n)), /Expected a document hash/);
    assert.throws(() => issueApproval(db, documentHash, "0x12"), /Expected a document hash/);
    const input = fresh();
    const nonce = input.message.nonce;
    assert.throws(() => acceptApproval(db, "' OR 1=1 --", sign(input)), /Invalid signing response/);
    assert.throws(() => acceptApproval(db, nonce, sign(input, 2n)), /E_SIG_INVALID/);
    for (const response of [null, [], { origin: input.origin, signature: "0x12" },
      { ...sign(input), origin: 123 }, { ...sign(input), origin: "x".repeat(1025) }]) {
      assert.throws(() => acceptApproval(db, nonce, response), /Invalid signing response/);
    }
    assert.throws(() => acceptApproval(db, `0x${"00".repeat(32)}`, sign(input)), /Unknown/);
    pending(nonce);
    const approved = acceptApproval(db, nonce, {
      ...sign(input), account: "claimed-admin", publicKeyHex: publicKey(2n), digestHex: "untrusted",
    });
    assert.equal(approved.public_key, publicKey(1n), "the stored key, not response echoes, identifies the signer");
    assert.throws(() => acceptApproval(db, nonce, sign(input)), /already approved/);
    const reopened = new DatabaseSync(path);
    try { assert.throws(() => acceptApproval(reopened, nonce, sign(input)), /already approved/); }
    finally { reopened.close(); }
    passed("trusted signer, malformed replies, ignored identity echoes and durable replay rejection");

    const expired = fresh();
    clock = Number(expired.message.expiresAt);
    assert.throws(() => acceptApproval(db, expired.message.nonce, sign(expired)), /expired/);
    pending(expired.message.nonce);
    passed("expiry is exclusive at the deadline");

    for (const [name, change] of [
      ["expiry during verification", row => { clock = row.expires_at; }],
      ["revocation", row => { db.prepare("DELETE FROM approval_requests WHERE nonce = ?").run(row.nonce); }],
      ["changed grant", row => { db.prepare("UPDATE approval_requests SET document_hash = ? WHERE nonce = ?").run(`0x${"cd".repeat(32)}`, row.nonce); }],
    ]) {
      const request = fresh();
      const restore = afterSelect(db, change);
      try { assert.throws(() => acceptApproval(db, request.message.nonce, sign(request)), /Request expired, changed, revoked/); }
      finally { restore(); }
      assert.equal(db.prepare("SELECT count(*) AS n FROM approval_requests WHERE nonce = ? AND approved_at IS NOT NULL").get(request.message.nonce).n, 0);
      passed(`atomic update rejects ${name} after the pending read`);
    }

    const race = fresh();
    const gate = new SharedArrayBuffer(4);
    for (let i = 0; i < 2; i++) workers.push(new Worker(new URL(import.meta.url), {
      workerData: { path, gate, nonce: race.message.nonce, response: sign(race) },
    }));
    const results = await Promise.all(workers.map(async worker => {
      const [result] = await once(worker, "message", { signal: AbortSignal.timeout(10000) });
      return result;
    }));
    assert.equal(Atomics.load(new Int32Array(gate), 0), 2);
    assert.equal(results.filter(result => result.ok).length, 1, JSON.stringify(results));
    assert.match(results.find(result => !result.ok).error, /Request expired, changed, revoked or was already approved/);
    assert.equal(db.prepare("SELECT count(*) AS n FROM approval_requests WHERE nonce = ? AND approved_at IS NOT NULL").get(race.message.nonce).n, 1);
    passed("two worker connections read the same pending request; exactly one approves");
    console.log(`${checks} approval-example checks passed (real BLS and SQLite; no wallet/browser or independent encoder claim).`);
  } finally {
    await Promise.all(workers.map(worker => worker.terminate()));
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }
}
