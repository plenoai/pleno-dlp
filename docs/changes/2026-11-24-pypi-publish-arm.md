Owners: architect

Publish wheels to PyPI with an inline trusted-publishing exchange (GitHub
OIDC → PyPI mint-token → twine) because pypa/gh-action-pypi-publish ships
an amd64-only container that fails with `exec format error` on the arm64
release pool (v0.70.1).
