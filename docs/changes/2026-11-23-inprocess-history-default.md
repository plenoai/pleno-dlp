Owners: core-engineer, qa

Parallel history walks now render patches in process by default, whatever their length; the 20k-commit cost rule that sent long histories to `git log -p` is gone. Unsharded histories keep git. Hyperfine -r5 medians, wall s / CPU-s including git children, with identical finding sets: croc 0.232 / 2.44 (main 0.260 / 2.76), django 2.25 / 32.1 (2.38 / 41.7), rails 2.94 / 36.0 (3.15 / 44.3). `PLENO_DLP_GIT_PATCH_RENDER=git` keeps `git log -p`. Closes #1019.
