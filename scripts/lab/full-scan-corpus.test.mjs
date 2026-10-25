// Offline regression tests for the corpus passive fence (full-scan-corpus.mjs).
// No network: a stub stands in for fetch and, like the real runtime, follows
// redirects itself when it is allowed to, so a fence that hands it
// redirect: "follow" leaks every later hop.
//
//   node --test scripts/lab/full-scan-corpus.test.mjs
//   FENCE_MODULE=/path/to/other/full-scan-corpus.mjs node --test scripts/lab/full-scan-corpus.test.mjs
// FENCE_MODULE re-runs the same tests against another copy (e.g. an older head's
// file saved as scripts/lab/old-full-scan-corpus.mjs, beside lab-scan.mjs, which it
// imports). Against 842d5e9 these tests fail 14 of 17: it let the runtime follow
// redirects, so hops into the operator's network were fetched unseen.
//
// Limit: a public NAME that resolves to a private address is not refused; the
// fence checks literal addresses and local-only names, not DNS answers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";

const modulePath = process.env.FENCE_MODULE || fileURLToPath(new URL("./full-scan-corpus.mjs", import.meta.url));

// Imported once, under a fetch that records: importing must not touch the network.
const importCalls = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (input) => { importCalls.push(String(input?.url ?? input)); throw new TypeError("offline"); };
const exitCodeBefore = process.exitCode;
const { passiveFence } = await import(pathToFileURL(modulePath).href);
globalThis.fetch = realFetch;

function network(table) {
  const calls = [];
  const stub = async (input, init = {}) => {
    let url = typeof input === "string" ? input : input.url;
    const mode = init.redirect ?? (typeof input === "object" ? input.redirect : undefined) ?? "follow";
    for (let i = 0; i < 25; i++) {
      calls.push({ url, mode });
      const row = table[url] || { status: 200 };
      const redirect = row.status >= 300 && row.status < 400;
      const res = new Response(redirect ? null : "ok", { status: row.status, headers: row.location ? { location: row.location } : {} });
      Object.defineProperty(res, "url", { value: url });
      if (!redirect || mode === "manual") return res;
      url = new URL(row.location, url).href;
    }
    throw new TypeError("stub redirect loop");
  };
  return { stub, calls };
}
const refusedWith = (promise) => assert.rejects(promise, TypeError);

test("importing the corpus runner has no side effect: no network, no CLI run", () => {
  assert.equal(importCalls.length, 0);
  assert.equal(process.exitCode, exitCodeBefore);
  assert.equal(typeof passiveFence, "function");
});

test("a followed home-page redirect is fetched hop by hop, never by the runtime", async () => {
  const { stub, calls } = network({ "https://ex.com/": { status: 301, location: "https://www.ex.com/en/" } });
  const f = passiveFence("ex.com", stub);
  const res = await f.fence("https://ex.com/", { redirect: "follow" });
  assert.equal(res.status, 200);
  assert.equal(res.url, "https://www.ex.com/en/");
  assert.ok(calls.every((c) => c.mode === "manual"), JSON.stringify(calls));
  assert.deepEqual(f.allowed.map((a) => a.why), ["home_page", "redirect_of_home_page"]);
});

for (const target of [
  "http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/",
  "http://172.20.0.1/", "http://100.64.0.1/", "http://[::1]/", "http://[fd00::1]/",
  "http://localhost:8080/", "http://router.local/", "http://2130706433/",
]) {
  test(`a home-page redirect to ${target} is refused and never fetched`, async () => {
    const { stub, calls } = network({ "https://ex.com/": { status: 302, location: target } });
    const f = passiveFence("ex.com", stub);
    await refusedWith(f.fence("https://ex.com/"));
    assert.equal(calls.length, 1, JSON.stringify(calls));
    assert.equal(f.refused.length, 1);
  });
}

test("a public cross-host redirect is followed, as one browser visit would", async () => {
  const { stub } = network({ "https://ex.com/": { status: 302, location: "https://login.idp.example/sso?x=1" } });
  const res = await passiveFence("ex.com", stub).fence("https://ex.com/");
  assert.equal(res.url, "https://login.idp.example/sso?x=1");
});

test("manual mode returns the 3xx; only the announced target is then admitted", async () => {
  const { stub } = network({ "https://ex.com/": { status: 301, location: "https://ex.com/en/" } });
  const f = passiveFence("ex.com", stub);
  assert.equal((await f.fence("https://ex.com/", { redirect: "manual" })).status, 301);
  assert.equal((await f.fence("https://ex.com/en/", { redirect: "manual" })).status, 200);
  await refusedWith(f.fence("https://ex.com/admin"));
  await refusedWith(f.fence("https://ex.com/", { method: "POST" }));
});

test("a data source redirecting off the data hosts is refused at that hop", async () => {
  const { stub, calls } = network({ "https://crt.sh/?q=ex.com": { status: 302, location: "https://tracker.example/x" } });
  await refusedWith(passiveFence("ex.com", stub).fence("https://crt.sh/?q=ex.com"));
  assert.ok(!calls.some((c) => c.url.startsWith("https://tracker.example")), JSON.stringify(calls));
});

test("redirect chains stop after five redirects", async () => {
  const table = {};
  for (let i = 0; i < 10; i++) table[`https://ex.com/${i ? `${i}/` : ""}`] = { status: 302, location: `https://ex.com/${i + 1}/` };
  const { stub, calls } = network(table);
  await refusedWith(passiveFence("ex.com", stub).fence("https://ex.com/"));
  assert.ok(calls.length <= 6, String(calls.length));
});

test("a Request object with the default follow mode cannot leak a hop", async () => {
  const { stub, calls } = network({ "https://ex.com/": { status: 302, location: "http://192.168.1.1/" } });
  await refusedWith(passiveFence("ex.com", stub).fence(new Request("https://ex.com/")));
  assert.equal(calls.length, 1, JSON.stringify(calls));
});
