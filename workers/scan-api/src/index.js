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
          { status: "error", message: "Invalid domain" },
          { status: 400 }
        );
      }

      const userId = "user_demo";
      const domainId = createId("domain");
      const scanId = createId("scan");
      const createdAt = new Date().toISOString();
      const reportKey = `reports/${scanId}.json`;

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

      await env.cybermeters_reports.put(
        reportKey,
        JSON.stringify({
          scan_id: scanId,
          domain_id: domainId,
          domain,
          status: "queued",
          created_at: createdAt,
          report_type: "initial_scan_record",
          message: "Initial queued scan report stored in R2"
        }, null, 2),
        {
          httpMetadata: {
            contentType: "application/json"
          }
        }
      );

      return Response.json({
        status: "queued",
        scan_id: scanId,
        domain_id: domainId,
        domain,
        report_key: reportKey,
        message: "Scan request stored in D1 and initial report stored in R2"
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

    if (
      request.method === "GET" &&
      url.pathname.startsWith("/api/scans/")
    ) {
      const scanId = url.pathname.split("/").pop();

      const scan = await env.cybermeters_db.prepare(
        `SELECT id, domain_id, domain, status, created_at
         FROM scans
         WHERE id = ?`
      )
        .bind(scanId)
        .first();

      if (!scan) {
        return Response.json(
          { error: "Scan not found" },
          { status: 404 }
        );
      }

      return Response.json({
        scan,
        report_key: `reports/${scan.id}.json`
      });
    }

    if (
      request.method === "GET" &&
      url.pathname.startsWith("/api/domain/") &&
      url.pathname.endsWith("/history")
    ) {
      const parts = url.pathname.split("/");
      const domain = decodeURIComponent(parts[3]);

      if (!isValidDomain(domain)) {
        return Response.json(
          { error: "Invalid domain" },
          { status: 400 }
        );
      }

      const history = await env.cybermeters_db.prepare(
        `SELECT id, domain_id, domain, status, created_at
         FROM scans
         WHERE domain = ?
         ORDER BY created_at DESC`
      )
        .bind(domain)
        .all();

      return Response.json({
        domain,
        scans: history.results
      });
    }

    return Response.json(
      { error: "Not found" },
      { status: 404 }
    );
  }
};
