// The name each connected client registered, for the connections page (founder,
// 21 Oct 2026: cards titled with raw client ids). Display only: the name is the
// client's own word, never an identity or authorisation fact. Only registered
// (opaque) ids are looked up — a client whose id is a URL would make the
// provider fetch a remote document, so it is never looked up here — distinct
// ids only, at most `max`, and a failed lookup leaves that name empty.
export async function withMcpClientNames(connections, lookupClient, { max = 10 } = {}) {
  const list = Array.isArray(connections) ? connections : [];
  const ids = [...new Set(list.map((c) => c?.client_id)
    .filter((id) => typeof id === "string" && id.length > 0 && id.length <= 256 && !/^[a-z][a-z0-9+.-]*:/i.test(id)))].slice(0, max);
  const names = new Map();
  await Promise.all(ids.map(async (id) => {
    try {
      const client = await lookupClient(id);
      const name = typeof client?.clientName === "string"
        ? client.clientName.replace(/[\u0000-\u001f\u007f\p{Cf}]/gu, "").trim().slice(0, 80)
        : "";
      if (name) names.set(id, name);
    } catch { /* an unreadable registration simply has no name to show */ }
  }));
  return list.map((c) => ({ ...c, client_name: names.get(c?.client_id) ?? null }));
}
