---
'@ai-oauth-sdk/browser': patch
---

Stop offering a cleartext origin as a provider's redirect URI in `resolveBrowserFlow()`.

The first rule read "the origin is not loopback and the provider accepts an arbitrary HTTPS redirect". It never tested that the origin was in fact HTTPS, and `originRoot()` copies `origin.protocol` verbatim, so an app served from a non-loopback *cleartext* origin — `http://192.168.1.50:8080/` during development, `http://tools.corp.lan/` for an intranet tool — was handed a popup flow with an `http://` redirect URI. The function's own JSDoc already said "accepts an arbitrary HTTPS redirect"; the code did not implement that sentence.

`openrouter` is the one bundled provider declaring `acceptsHttpsRedirect: true`, and it names its redirect `callback_url`, so the cleartext URL went on the wire and the authorization code came back to the page over cleartext — readable by anyone on the network path, on exactly the kind of network where an app is served over plain HTTP in the first place.

Rule 1 now also requires `origin.protocol === 'https:'`. Loopback origins are untouched: they are caught by rule 2 (`loopbackPort: 0`) and by rule 3, and traffic to them never leaves the machine — the same exemption RFC 8252 makes and that `providerFromDiscovery()` makes for discovered endpoints. Genuine HTTPS origins are entirely unaffected.

`PasteHint` gains a third kind, `insecure-origin`, because the condition alone would have been a worse bug than the one it fixed. With rule 1 no longer firing, `openrouter` — no device flow, no `hostedUri` — fell through to `paste` with the `unreachable` hint, whose message tells the user the page will fail to load and to copy the whole address bar. Neither is true here: the redirect address is fine, the origin is the problem, and the remedy is to serve the app over https or from localhost. A UI that switches on `hint.kind` will need a branch for it; one that renders `hint.message` needs no change.
