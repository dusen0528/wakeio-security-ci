// Shared synthetic loopback fixture for finding control evidence and replay tests.
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";

export const PROOF_ENV = {
  PROOF_OWNER_AUTH: "Bearer proof-owner-synthetic-token",
  PROOF_OTHER_AUTH: "Bearer proof-other-synthetic-token",
};
export const PROOF_CANARY = "proof-synthetic-canary-value";

export interface ProofFixture {
  baseUrl: string;
  /** Mutable at runtime: the same policy can observe a leak, a fix or a broken owner control. */
  behaviour: { leakOther: boolean; leakAnonymous: boolean; ownerFailsAfter: number | null };
  requests: Array<{ path: string; actor: string }>;
  close(): Promise<void>;
}

export async function startProofFixture(): Promise<ProofFixture> {
  const behaviour: ProofFixture["behaviour"] = { leakOther: true, leakAnonymous: false, ownerFailsAfter: null };
  const requests: ProofFixture["requests"] = [];
  let ownerDocumentReads = 0;
  const server: Server = createServer((request, response) => {
    const actor = request.headers.authorization === PROOF_ENV.PROOF_OWNER_AUTH ? "owner"
      : request.headers.authorization === PROOF_ENV.PROOF_OTHER_AUTH ? "other" : "anonymous";
    requests.push({ path: request.url ?? "", actor });
    const send = (status: number, value: unknown) => {
      response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value));
    };
    if (request.url === "/whoami") {
      return actor === "anonymous" ? send(401, { error: "denied" }) : send(200, { userId: `${actor}-principal`, orgId: "proof-org" });
    }
    if (request.url !== "/documents/doc-1") return send(404, { error: "missing" });
    const record = { id: "doc-1", canary: PROOF_CANARY };
    if (actor === "owner") {
      ownerDocumentReads += 1;
      if (behaviour.ownerFailsAfter !== null && ownerDocumentReads > behaviour.ownerFailsAfter) return send(404, { error: "gone" });
      return send(200, record);
    }
    if (actor === "other") return behaviour.leakOther ? send(200, record) : send(403, { error: "denied" });
    return behaviour.leakAnonymous ? send(200, record) : send(401, { error: "denied" });
  });
  await new Promise<void>((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    behaviour,
    requests,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    },
  };
}

export function proofPolicy(baseUrl: string) {
  return {
    version: 2,
    baseUrl,
    actors: [
      { id: "owner", authorizationEnv: "PROOF_OWNER_AUTH", identity: { path: "/whoami", status: 200, jsonPointer: "/userId", equals: "owner-principal", organization: { jsonPointer: "/orgId", equals: "proof-org" } } },
      { id: "other", authorizationEnv: "PROOF_OTHER_AUTH", identity: { path: "/whoami", status: 200, jsonPointer: "/userId", equals: "other-principal", organization: { jsonPointer: "/orgId", equals: "proof-org" } } },
      { id: "anonymous" },
    ],
    cases: [{
      id: "owner-document",
      path: "/documents/doc-1",
      allow: { actor: "owner", status: 200, resource: { jsonPointer: "/id", equals: "doc-1" }, protected: { jsonPointer: "/canary", equals: PROOF_CANARY } },
      deny: [{ actor: "other", statuses: [403] }, { actor: "anonymous", statuses: [401] }],
    }],
  };
}
