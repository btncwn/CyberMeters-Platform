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

    // ── Workspace Routes ──────────────────────────────────────────────────────

    // GET /api/workspaces
    if (request.method === "GET" && url.pathname === "/api/workspaces") {
      try {
        const result = await env.cybermeters_db
          .prepare(`SELECT id, name, created_at FROM workspaces ORDER BY created_at DESC`)
          .all();
        return Response.json({ workspaces: result.results });
      } catch {
        return Response.json({ error: "Database error" }, { status: 500 });
      }
    }

    // POST /api/workspaces
    if (request.method === "POST" && url.pathname === "/api/workspaces") {
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const name = (body.name || "").trim();
      if (!name) {
        return Response.json({ error: "name is required" }, { status: 400 });
      }
      const id = `workspace_${crypto.randomUUID()}`;
      const created_at = new Date().toISOString();
      try {
        await env.cybermeters_db
          .prepare(`INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)`)
          .bind(id, name, created_at)
          .run();
        return Response.json({ workspace: { id, name, created_at } }, { status: 201 });
      } catch {
        return Response.json({ error: "Database error" }, { status: 500 });
      }
    }

    // Routes that need a workspace ID
    // Matches: /api/workspaces/:id
    //          /api/workspaces/:id/domains
    //          /api/workspaces/:id/domains/:domainId
    const workspaceMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)(\/domains(?:\/([^/]+))?)?$/
    );

    if (workspaceMatch) {
      const workspaceId  = workspaceMatch[1];
      const domainSegment = workspaceMatch[2]; // "/domains" | "/domains/:domainId" | undefined
      const linkedDomainId = workspaceMatch[3]; // domainId component, if present

      // Verify workspace exists for all sub-routes
      let workspace;
      try {
        workspace = await env.cybermeters_db
          .prepare(`SELECT id, name FROM workspaces WHERE id = ?`)
          .bind(workspaceId)
          .first();
      } catch {
        return Response.json({ error: "Database error" }, { status: 500 });
      }
      if (!workspace) {
        return Response.json({ error: "Workspace not found" }, { status: 404 });
      }

      // DELETE /api/workspaces/:id/domains/:domainId
      // Remove workspace↔domain link only — does NOT delete the domain row.
      if (request.method === "DELETE" && domainSegment && linkedDomainId) {
        try {
          const del = await env.cybermeters_db
            .prepare(
              `DELETE FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?`
            )
            .bind(workspaceId, linkedDomainId)
            .run();
          if (del.meta.changes === 0) {
            return Response.json({ error: "Domain link not found" }, { status: 404 });
          }
          return Response.json({
            success: true,
            workspace_id: workspaceId,
            domain_id: linkedDomainId,
          });
        } catch {
          return Response.json({ error: "Database error" }, { status: 500 });
        }
      }

      // GET /api/workspaces/:id/domains
      // Returns domains linked to this workspace, enriched with latest scan data.
      if (request.method === "GET" && domainSegment === "/domains") {
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT
                 d.id          AS domain_id,
                 d.domain,
                 s.id          AS last_scan_id,
                 s.score       AS latest_score,
                 s.status      AS latest_status,
                 s.created_at  AS last_scanned_at
               FROM workspace_domains wd
               JOIN   domains d ON d.id = wd.domain_id
               LEFT JOIN scans s ON s.id = (
                 SELECT id FROM scans
                 WHERE  domain_id = d.id
                 ORDER  BY created_at DESC
                 LIMIT  1
               )
               WHERE wd.workspace_id = ?
               ORDER BY d.domain ASC`
            )
            .bind(workspaceId)
            .all();
          return Response.json({ workspace_id: workspaceId, domains: result.results });
        } catch {
          return Response.json({ error: "Database error" }, { status: 500 });
        }
      }

      // POST /api/workspaces/:id/domains
      // Reuses existing domain row if present; creates one otherwise.
      // Idempotent link via INSERT OR IGNORE.
      if (request.method === "POST" && domainSegment === "/domains") {
        let body;
        try { body = await request.json(); } catch { body = {}; }
        const raw = (body.domain || "").trim().toLowerCase();
        if (!isValidDomain(raw)) {
          return Response.json(
            { error: "domain is required and must be a valid domain" },
            { status: 400 }
          );
        }

        try {
          // Reuse existing domain row or create new one
          let domainRow = await env.cybermeters_db
            .prepare(`SELECT id, domain FROM domains WHERE domain = ? LIMIT 1`)
            .bind(raw)
            .first();

          if (!domainRow) {
            const newDomainId = createId("domain");
            await env.cybermeters_db
              .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
              .bind(newDomainId, "user_demo", raw)
              .run();
            domainRow = { id: newDomainId, domain: raw };
          }

          // Link domain to workspace — silent no-op if already linked
          await env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id)
               VALUES (?, ?)`
            )
            .bind(workspaceId, domainRow.id)
            .run();

          return Response.json(
            {
              domain: {
                domain_id:    domainRow.id,
                domain:       domainRow.domain,
                workspace_id: workspaceId,
              },
            },
            { status: 201 }
          );
        } catch {
          return Response.json({ error: "Database error" }, { status: 500 });
        }
      }
    }

    return Response.json(
      { error: "Not found" },
      { status: 404 }
    );
  }
};
