// Import-only DMARC ingest configuration.
//
// Keep this module dependency-free. Resolution/scoring engines need the hosted
// RUA hostname, but importing the full dmarc-ingest implementation from those
// engines pulls in the email lifecycle and managed-alert graph during module
// initialisation. That creates a TDZ cycle before alert-gate has initialised its
// channel constants.
export const RUA_INBOUND_DOMAIN_DEFAULT = "reports.cybermeters.com";
