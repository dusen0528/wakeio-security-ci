# URL observation implementation note

The URL pass remains a bounded passive scan. It uses the original root GET and
the existing same-origin JavaScript GETs only. It does not send `Origin`, add
credentials, execute JavaScript, follow source-map/debug targets, probe extra
paths, or query another origin.

## Semantics used

- [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS) and
  [MDN Fetch](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch)
  define `Access-Control-Allow-Origin: *` as valid for non-credentialed public
  reads. `Access-Control-Allow-Credentials: true` cannot make a wildcard
  credentialed read valid, so the scanner records that pair as a low-confidence
  candidate without claiming a read, exposure, or browser bypass. ACAO/ACAC/Vary
  are summarized as a redacted passive note; no origin mutation is attempted.
- [MDN SourceMap](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/SourceMap)
  documents response-header and source annotation map locations. A
  `SourceMap`/`X-SourceMap` header or `sourceMappingURL` annotation is therefore
  a disclosure candidate only. Its value is never retained and the map is not
  fetched.
- [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys)
  distinguishes browser-safe publishable/legacy `anon` keys from backend-only
  secret/legacy `service_role` keys. The URL detector exempts recognizable
  `sb_publishable_` forms and decoded `anon` JWTs in a Supabase assignment,
  while recognizable `sb_secret_` forms and decoded `service_role` JWTs get a
  separate high-severity candidate. It does not validate a key or query
  Supabase.
- Public component findings require an explicit allow-listed library name and
  version in a fetched asset, a versioned public CDN URL, or a versioned asset
  name. A filename such as `react.min.js` is not enough. Findings are clues for
  lockfile/SBOM follow-up; no CVE or advisory is inferred. Version references
  used as examples include [React's version policy](https://react.dev/community/versioning-policy)
  and [jQuery's official CDN release guidance](https://jquery.com/download/).

Debug/stack markers, sensitive field markers, and source-map references remain
low-confidence candidates. Ordinary framework runtime markers are inventory
notes only because they are normal public bootstrap metadata; a sensitive
field or value still has to match its own bounded detector. Raw token values,
header values, map targets, and credential-bearing URLs are excluded from
findings.
