# goapiauth — Claude Code instructions

A public Go library, not a server. There is no `main` package and nothing to
install; it ships as git tags. Its consumers are Go web APIs whose users log in
through an OIDC provider. `goclilogin` is the command-line client those users
log in with, and `gobrowserlogin` is the browser's login.

Written to be used by strangers. Treat the exported API, the README and the
godoc as the product. A change that suits the internal consumers is not
automatically right.

## Never write the breaking-change trailer in a commit message

Those two words anywhere in a message cut a major once this repo is past 0.x.
A major from v1 on, on a Go module with no `/vN` path, is an outage rather than
a version: consumers resolving `@latest` stop seeing the tag. On 0.x,
`allow-initial-development-versions` cuts them as a minor. The analyzer matches
unanchored, so a commit that merely *discusses* the trailer cuts one too — say
"that marker" instead.

This repo carries no `.semrelrc`. Reaching 1.0 is dropping
`allow-initial-development-versions`. A deliberate v2 needs a `.semrelrc`
mapping `chore(release-major)` to a major, and the same release adds `/v2` to
the module path.
