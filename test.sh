#!/bin/bash
set -e

mkdir -p test-results
REQUEST='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
echo -en "Content-Length: ${#REQUEST}\r\n\r\n${REQUEST}" | zig build run | tr -d '\r' > test-results/actual-response.json

cat > test-results/expected-response.json << __EOF__
Content-Length: 323

{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"signatureHelpProvider":{"triggerCharacters":["(",","]},"textDocumentSync":1,"completionProvider":{"resolveProvider":false,"triggerCharacters":[".",":","@"]},"documentHighlightProvider":false,"codeActionProvider":false,"workspace":{"workspaceFolders":{"supported":true}}}}}Content-Length: 101

{"jsonrpc":"2.0","method":"window/logMessage","params":{"type":4,"message":"0 bytes read; exiting!"}}
__EOF__

echo >> test-results/actual-response.json
diff test-results/actual-response.json test-results/expected-response.json
exit $?