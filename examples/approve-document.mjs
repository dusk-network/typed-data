/**
 * Backend example: consume a one-time grant to approve a document hash.
 * Node 24; run the executable checks with `npm run build && npm run test:example`.
 * This is application code, not a package export, HTTP server, or login protocol.
 */
import { randomBytes } from "node:crypto";
import { verifyTypedDataSignature } from "@dusk/typed-data/bls";

// Server configuration, never taken from the submitted signing response.
const POLICY = Object.freeze({ chainId: "dusk:2", origin: "https://app.example" });

// ponytail: SQLite is single-host storage; use the app's shared transactional DB for multiple hosts.
export function initApprovalStore(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS approval_requests (
    nonce TEXT PRIMARY KEY,
    document_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    approved_at INTEGER
  ) STRICT`);
}

function typedRequest(row) {
  // Fresh application-owned schema/domain; no client-supplied type definitions.
  return {
    domain: { name: "Example Documents", version: "1", chainId: POLICY.chainId },
    types: {
      DuskTypedDataDomain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId", type: "string" },
        { name: "verifyingContract", type: "bytes32" },
      ],
      DocumentApproval: [
        { name: "documentHash", type: "bytes32" },
        { name: "nonce", type: "bytes32" },
        { name: "expiresAt", type: "uint64" },
      ],
    },
    primaryType: "DocumentApproval",
    message: {
      documentHash: row.document_hash,
      nonce: row.nonce,
      expiresAt: String(row.expires_at), // Unix seconds, not milliseconds.
    },
    origin: POLICY.origin,
  };
}

/**
 * Trusted server operation: select the document and authorized key from application
 * state, NOT from an unauthenticated client's proposed identity/permission.
 * The resulting row is the one-time authorization grant. Delete it to revoke it;
 * never recycle nonces. An approved row is the document-approval action itself.
 */
export function issueApproval(db, documentHash, authorizedPublicKeyHex) {
  if (typeof documentHash !== "string" || !/^0x[0-9a-f]{64}$/i.test(documentHash) ||
      typeof authorizedPublicKeyHex !== "string" || !/^0x[0-9a-f]{192}$/i.test(authorizedPublicKeyHex)) {
    throw new Error("Expected a document hash and an application-authorized BLS public key");
  }
  const nonce = `0x${randomBytes(32).toString("hex")}`;
  const row = db.prepare(`INSERT INTO approval_requests
    (nonce, document_hash, public_key, expires_at)
    VALUES (?, ?, ?, unixepoch() + 300) RETURNING *`
  ).get(nonce, documentHash, authorizedPublicKeyHex);
  return typedRequest(row);
}

/** Verify a parsed JSON reply and atomically record approval, or throw. */
export function acceptApproval(db, nonce, response) {
  if (typeof nonce !== "string" || !/^0x[0-9a-f]{64}$/i.test(nonce) ||
      !response || typeof response !== "object" || Array.isArray(response) ||
      typeof response.origin !== "string" || response.origin.length > 1024 ||
      typeof response.signature !== "string" || !/^0x[0-9a-f]{96}$/i.test(response.signature)) {
    throw new Error("Invalid signing response");
  }
  const row = db.prepare(`SELECT * FROM approval_requests
    WHERE nonce = ? AND approved_at IS NULL AND expires_at > unixepoch()`
  ).get(nonce);
  if (!row) throw new Error("Unknown, expired, revoked or already approved request");

  const result = verifyTypedDataSignature(
    { ...typedRequest(row), origin: response.origin },
    response.signature,
    row.public_key, // Not response.account or response.publicKeyHex.
    POLICY,
  );
  if (!result.ok) throw new Error(result.code);

  // One atomic statement consumes the nonce AND records the action. Recheck expiry,
  // revocation and the exact verified grant even if another connection raced us.
  const approved = db.prepare(`UPDATE approval_requests SET approved_at = unixepoch()
    WHERE nonce = ? AND public_key = ? AND document_hash = ? AND expires_at = ?
      AND approved_at IS NULL AND expires_at > unixepoch()
    RETURNING document_hash, public_key, approved_at`
  ).get(nonce, row.public_key, row.document_hash, row.expires_at);
  if (!approved) throw new Error("Request expired, changed, revoked or was already approved");
  return approved;
}
