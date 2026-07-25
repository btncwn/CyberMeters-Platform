// Build-only Worker entry for the P1 tr46 compatibility gate.
// It is never used by the production Worker configuration.
import { canonicalizeDmarcbisDomain } from "../../workers/scan-api/src/engines/dmarcbis-idna.js";

export default {
  async fetch() {
    const result = canonicalizeDmarcbisDomain("bücher.example");
    return Response.json({ alabel: result.alabel });
  },
};
