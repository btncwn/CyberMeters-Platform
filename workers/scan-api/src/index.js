function createId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function isValidDomain(domain) {
  return typeof domain === "string" &&
    /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({
        status: "ok",
        service: "cybermeters-scan-api"
      });
    }

    if (request.method === "POST" && url.pathname === "/api/scan") {
      const body = await request.json();
      const domain = body.domain;

      if (!isValidDomain(domain)) {
        return Response.json(
          {
            status: "error",
            message: "Invalid domain"
          },
          {
            status: 400
          }
        );
      }

      const userId = "user_demo";
      const domainId = createId("domain");
      const scanId = createId("scan");

      await env.cybermeters_db.prepare(
        `INSERT INTO users (id, email, name, plan)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
        .bind(userId, "demo@cybermeters.com", "Demo User", "free")
        .run();

      await env.cybermeters_db.prepare(
        `INSERT INTO domains (id, user_id, domain)
         VALUES (?, ?, ?)`
      )
        .bind(domainId, userId, domain)
        .run();

      await env.cybermeters_db.prepare(
        `INSERT INTO scans (id, domain_id, domain, status)
         VALUES (?, ?, ?, ?)`
      )
        .bind(scanId, domainId, domain, "queued")
        .run();

      return Response.json({
        status: "queued",
        scan_id: scanId,
        domain_id: domainId,
        domain,
        message: "Scan request stored in D1"
      });
    }

    if (request.method === "GET" && url.pathname === "/api/scans") {
      const result = await env.cybermeters_db.prepare(
        `SELECT id, domain, status, created_at
         FROM scans
         ORDER BY created_at DESC
         LIMIT 20`
      ).all();

      return Response.json({
        scans: result.results
      });
    }

    return Response.json(
      {
        error: "Not found"
      },
      {
        status: 404
      }
    );
  }
};
