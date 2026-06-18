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

    // ── GET /health ──────────────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({
        status: "ok",
        service: "cybermeters-scan-api"
      });
    }

    // ── POST /api/scan ───────────────────────────────────────────────────
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
          cyber_metrics_score: 0,
          risk_level: "unknown",
          findings: [],
          recommendations: [],
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

    // ── GET /api/scans ───────────────────────────────────────────────────
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

    // ── GET /api/scans/:id/report ────────────────────────────────────────
    // Must be checked BEFORE the generic /api/scans/:id handler below.
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/report$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];

      // 1. Verify the scan exists in D1
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

      // 2. Read the report from R2
      const reportKey = `reports/${scanId}.json`;
      const obj = await env.cybermeters_reports.get(reportKey);

      if (!obj) {
        return Response.json(
          { error: "Report not found" },
          { status: 404 }
        );
      }

      // 3. Parse the stored JSON
      const raw = await obj.json();

      // 4. Return structured response — all required fields guaranteed,
      //    extra fields from the report passed through as-is.
      return Response.json({
        scan_id: scan.id,
        domain: scan.domain,
        status: scan.status,
        cyber_metrics_score: raw.cyber_metrics_score ?? 0,
        risk_level: raw.risk_level ?? "unknown",
        findings: Array.isArray(raw.findings) ? raw.findings : [],
        recommendations: Array.isArray(raw.recommendations) ? raw.recommendations : [],
        // Pass through any additional fields the scan engine may have written
        ...(raw.report_type   ? { report_type: raw.report_type }     : {}),
        ...(raw.created_at    ? { created_at: raw.created_at }       : {}),
        ...(raw.completed_at  ? { completed_at: raw.completed_at }   : {}),
        ...(raw.message       ? { message: raw.message }             : {}),
      });
    }

    // ── GET /api/scans/:id ───────────────────────────────────────────────
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

    // ── GET /api/domain/:domain/history ──────────────────────────────────
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
