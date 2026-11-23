Owners: architect

Publish npm releases through staged publishing (`npm stage publish`, npm 11.19.0): the trusted publisher keeps direct publishing disabled, so each version needs maintainer 2FA approval before it is public. v0.71.3 failed with `OIDC permission denied` because CI attempted a direct publish.
