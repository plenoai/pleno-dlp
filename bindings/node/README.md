# pleno-dlp

Node.js bindings for [pleno-dlp](https://github.com/plenoai/pleno-dlp), a
secret and PII scanner. Scan buffers and files, verify a secret with its
provider, and revoke leaked credentials.

```js
import { scanPaths } from 'pleno-dlp';

for (const f of scanPaths('src')) {
  console.log(f.detector, f.path, f.line, f.redacted);
}
```

Scans are offline and findings are redacted unless you pass
`{ verify: true }` or `{ includeRaw: true }`. `revoke()` requires
`{ confirm: true }` or `{ dryRun: true }`.

See the [library documentation](https://github.com/plenoai/pleno-dlp/blob/main/docs/library.md)
for the full API, supported platforms, and stability policy.
