TLS fixtures are generated with the installed OpenSSL in a private temporary
directory at test setup. No certificate private keys are stored in the repository.
The valid/wrong-host leaves have fixed 2025–2040 validity; the expired leaf has
fixed 2020–2021 validity. A fresh local CA signs each set.

The test hook removes all generated files. The validator also owns their parent
temporary directory, so its cleanup covers child-test timeout or failure.
Connections replace the endpoint with 127.0.0.1 and never contact the example
hostname or public literal from the request. Test CA roots are never used by
the deployed collector. Run `node scripts/validate-network-probe.js` from the root.
