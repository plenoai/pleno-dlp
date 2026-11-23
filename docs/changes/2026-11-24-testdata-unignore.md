Owners: architect, qa

Commit the missing split-zip fixtures (`pkg/archive/testdata/zipspan/*.zip`)
and add `!**/testdata/**` to `.gitignore`. A contributor-global `*.zip`
ignore silently dropped them from PR #951, so local tests passed while the
v0.71.1 release race run failed on missing files.
