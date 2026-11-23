Owners: connector-engineer, qa

Scan merge resolutions of text marked binary only in `.git/info/attributes`: native merge forced-text rendering already cleared tree, global, and system attributes, but `$GIT_DIR/info/attributes` still applied. The render now runs against a per-walk temporary git directory that borrows the object store via `objects/info/alternates` (copying `shallow`) and has no `info/attributes`; it is removed when the walk ends. `TestChunks_NativeMergeResolutionInfoAttributesBinaryText` fails without the change (#998, epic #817).
