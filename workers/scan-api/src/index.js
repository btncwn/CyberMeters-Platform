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

      return Response.json({
        status: "queued",
        domain: body.domain,
        message: "Scan request accepted"
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
