# Industry blind-spot report: the shared 25/44 leaky-repo miss

The headline is not a pleno-dlp win. [`comparison.md`](comparison.md) §3
already measured it: on `Plazmaz/leaky-repo` (the community-standard
scanner benchmark, 44 ground-truth files), pleno-dlp, trufflehog, and
gitleaks *each* individually hit only 13, 8, and 13 files — and **25 of
the 44 are missed by all three tools simultaneously**. Structured
config-file passwords and low-entropy secrets are an industry-wide
blind spot, not a two-tool race.

Issue #175 implemented structured-config credential extraction (16 new
detectors, three PR batches) aimed squarely at that 25-file set. This
report measures, file by file, how much of the shared blind spot
pleno-dlp closed for itself — and confirms, by re-running the same
pinned trufflehog/gitleaks versions on the same 25 files, that the rest
of the industry has not moved.

## Method

1. Identify the 25-file blind-spot set from `comparison.md`'s §3
   per-file matrix: every row where all three tool columns are `—`.
2. Pin `Plazmaz/leaky-repo` at the exact commit `comparison.md` uses
   (`2e95135`) and copy those 25 files, preserving their relative
   paths, into an isolated directory.
3. Build two pleno-dlp binaries from git history:
   - **pre-#175**: commit `b17537d`, the parent of #175's first batch
     (`0fcb461`) — includes every detector/engine change up to but not
     including #175.
   - **post-#175**: commit `7f41db7`, #175's third and final batch —
     confirmed to produce byte-identical file-hit results to current
     `main` (`06297a7`), so the delta below is #175's effect in
     isolation, not noise from unrelated later commits.
4. Run the canonical invocation from `comparison.md` against the
   isolated 25-file directory with both binaries, and separately with
   the same trufflehog 3.95.5 / gitleaks 8.30.1 versions `comparison.md`
   pins. Count unique files with at least one finding.
5. For every remaining miss, single-file re-scan with a positive
   control to classify it as a genuine detector gap vs. correct
   placeholder suppression (same audit discipline `comparison.md` §3
   and §9 use).

## The 25-file blind-spot set

| # | File | Secret kind |
|---|------|-------------|
| 1 | `.ssh/id_rsa.pub` | SSH public key (informative-only, 0 risk) |
| 2 | `web/var/www/public_html/wp-config.php` | WordPress DB password + auth keys/salts |
| 3 | `web/var/www/public_html/.htpasswd` | htpasswd password hash |
| 4 | `web/var/www/public_html/config.php` | PHP app config DB password |
| 5 | `.git-credentials` | git credential store (URL-embedded password) |
| 6 | `db/robomongo.json` | Mongolab/robomongo MongoDB + SSH creds |
| 7 | `web/js/salesforce.js` | Salesforce credentials in Node.js code |
| 8 | `.netrc` | netrc SMTP credentials |
| 9 | `filezilla/filezilla.xml` | FileZilla FTP password (base64) |
| 10 | `filezilla/recentservers.xml` | FileZilla recent-server FTP passwords |
| 11 | `config` | IRC NickServ password |
| 12 | `db/.pgpass` | PostgreSQL `.pgpass` password |
| 13 | `proftpdpasswd` | proftpd/cpanel crypt password hash |
| 14 | `ventrilo_srv.ini` | Ventrilo server passwords |
| 15 | `etc/shadow` | `/etc/shadow` password hash |
| 16 | `.esmtprc` | esmtp SMTP password |
| 17 | `web/django/settings.py` | Django `SECRET_KEY` |
| 18 | `web/ruby/config/master.key` | Rails master key |
| 19 | `deployment-config.json` | sftp-deployment (Atom) server creds |
| 20 | `.ftpconfig` | remote-ssh (Atom) SFTP/SSH creds + passphrase |
| 21 | `.remote-sync.json` | remote-sync (Atom) FTP/SFTP creds |
| 22 | `.vscode/sftp.json` | vscode-sftp SFTP creds |
| 23 | `sftp-config.json` | Sublime SFTP FTP/SFTP creds |
| 24 | `.idea/WebServers.xml` | JetBrains webserver password (encoded, not encrypted) |
| 25 | `high-entropy-misc.txt` | misc high-entropy strings (informative-only, 0 risk) |

## Before / after — pleno-dlp only

| | pre-#175 (`b17537d`) | post-#175 (`7f41db7`, = current `main` `06297a7`) |
|---|---:|---:|
| Blind-spot files hit (of 25) | **1 (4%)** | **20 (80%)** |

The single pre-#175 hit (`ventrilo_srv.ini`) came from the pre-existing
`HardcodedPassword` detector (#228, unrelated to #175) firing on its
generic low-entropy `key=value` password shape — not from anything
#175 added.

<details>
<summary>Per-file result and detector (post-#175 / current main)</summary>

| File | pre-#175 | post-#175 | Detector |
|------|:--:|:--:|---|
| `.ssh/id_rsa.pub` | — | — | *(informative-only, 0 risk — not a target)* |
| `web/var/www/public_html/wp-config.php` | — | ✓ | `PHPConfigSecret` |
| `web/var/www/public_html/.htpasswd` | — | ✓ | `UnixCryptHash` |
| `web/var/www/public_html/config.php` | — | ✓ | `PHPConfigSecret` |
| `.git-credentials` | — | ✓ | `GitCredentialsURL` |
| `db/robomongo.json` | — | ✓ | `JSONConfigSecret` |
| `web/js/salesforce.js` | — | ✓ | `JSLoginCallSecret` |
| `.netrc` | — | ✓ | `Netrc` |
| `filezilla/filezilla.xml` | — | ✓ | `FileZillaXML` |
| `filezilla/recentservers.xml` | — | ✓ | `FileZillaXML` |
| `config` (IRC) | — | — | *no detector covers bare `PASS` (only `password`/`passwd`/`pwd`/JSON `pass`)* |
| `db/.pgpass` | — | — | `Pgpass` exists and fires on a non-placeholder value (verified separately) — this fixture's demo value is the literal word `password`, correctly suppressed as a placeholder |
| `proftpdpasswd` | — | ✓ | `UnixCryptHash` |
| `ventrilo_srv.ini` | ✓ | ✓ | `HardcodedPassword` (pre-existing, #228) |
| `etc/shadow` | — | ✓ | `UnixCryptHash` |
| `.esmtprc` | — | — | `Esmtprc` exists and fires on a non-placeholder value (verified separately) — same placeholder reason as `.pgpass` |
| `web/django/settings.py` | — | ✓ | `DjangoConfigSecret` |
| `web/ruby/config/master.key` | — | ✓ | `RailsMasterKey` |
| `deployment-config.json` | — | ✓ | `JSONConfigSecret`, `DjangoConfigSecret` |
| `.ftpconfig` | — | ✓ | `JSONConfigSecret` |
| `.remote-sync.json` | — | ✓ | `JSONConfigSecret`, `DjangoConfigSecret` |
| `.vscode/sftp.json` | — | ✓ | `JSONConfigSecret`, `DjangoConfigSecret` |
| `sftp-config.json` | — | ✓ | `JSONConfigSecret`, `DjangoConfigSecret` |
| `.idea/WebServers.xml` | — | ✓ | `JetBrainsWebServers` |
| `high-entropy-misc.txt` | — | — | *(informative-only, 0 risk — not a target)* |

</details>

### The 5 remaining misses, honestly

- **2 are not real targets by design**: `.ssh/id_rsa.pub` (a public
  key) and `high-entropy-misc.txt` (labeled informative-only, 0 risk in
  the corpus's own ground truth). Excluding these, the addressable set
  is 23 files and pleno-dlp now hits 20/23 (87%).
- **2 are placeholder suppression, not a format gap**: `db/.pgpass` and
  `.esmtprc` both have dedicated detectors (`Pgpass`, `Esmtprc`) added
  in #175. Both fixtures' demo secret is the literal string
  `"password"` — the same placeholder value the detectors and
  `HardcodedPassword` already suppress everywhere else to avoid flooding
  users with doc-example false positives (`docs/comparison.md` §9 and
  the `#294` hardening note document the same tradeoff). Re-running
  both detectors against an otherwise-identical fixture with a
  non-placeholder value (`Sup3r$ecretPass!`) confirms both fire
  correctly — reproduce with:
  ```sh
  printf '#hostname:port:database:username:password\nlocalhost:5432:database:root:Sup3r$ecretPass!\n' > /tmp/pgpass-check/.pgpass
  printf 'identity "x@y.com"\nhostname smtp.gmail.com:587\nusername "x@y.com"\npassword "Sup3r$ecretPass!"\nstarttls required\n' > /tmp/pgpass-check/.esmtprc
  pleno-dlp scan filesystem /tmp/pgpass-check --quiet --format json
  ```
- **1 is a genuine remaining gap**: `config` (IRC NickServ,
  `IRC_PASS=irc_pass`). No shipped detector's keyword list includes the
  bare token `PASS` — `HardcodedPassword` requires `password`/`passwd`/
  `pwd`; `JSONConfigSecret` requires JSON syntax. Tracked as a follow-up
  candidate, not claimed as fixed here.

## Confirming the rest of the industry has not moved

Same 25-file directory, same pinned versions `comparison.md` uses:

```sh
trufflehog filesystem <dir> --no-verification --no-update --json --log-level=-1
gitleaks dir <dir> --no-banner --report-format json --report-path out.json --exit-code 0
```

| | trufflehog 3.95.5 | gitleaks 8.30.1 |
|---|---:|---:|
| Blind-spot files hit (of 25) | **0** | **0** |

Neither tool changed, and neither is expected to move on this specific
25-file set — this is the reproducible fact the report is named for:
the blind spot exists in tools pleno-dlp does not control, and closing
it is a per-tool engineering problem, not something that disappears on
its own.

## Reproducing

```sh
# 1. Pin the corpus at the exact commit comparison.md §3 uses.
git clone https://github.com/Plazmaz/leaky-repo.git
cd leaky-repo && git checkout 2e95135 && cd ..

# 2. Copy the 25 blind-spot files (see table above) into an isolated
#    directory, preserving relative paths, e.g.:
mkdir -p blindspot25
for f in .ssh/id_rsa.pub web/var/www/public_html/wp-config.php \
         web/var/www/public_html/.htpasswd web/var/www/public_html/config.php \
         .git-credentials db/robomongo.json web/js/salesforce.js .netrc \
         filezilla/filezilla.xml filezilla/recentservers.xml config \
         db/.pgpass proftpdpasswd ventrilo_srv.ini etc/shadow .esmtprc \
         web/django/settings.py web/ruby/config/master.key \
         deployment-config.json .ftpconfig .remote-sync.json \
         .vscode/sftp.json sftp-config.json .idea/WebServers.xml \
         high-entropy-misc.txt; do
  mkdir -p "blindspot25/$(dirname "$f")"
  cp "leaky-repo/$f" "blindspot25/$f"
done

# 3. Build the pre-#175 and post-#175 pleno-dlp binaries.
git -C pleno-dlp worktree add /tmp/pre175 b17537d
git -C pleno-dlp worktree add /tmp/post175 7f41db7   # == current main, verified above
go -C /tmp/pre175 build -o pleno-dlp-pre175 ./cmd/pleno-dlp
go -C /tmp/post175 build -o pleno-dlp-post175 ./cmd/pleno-dlp

# 4. Scan and count unique files with >=1 finding.
./pleno-dlp-pre175  scan filesystem blindspot25 --quiet --format json
./pleno-dlp-post175 scan filesystem blindspot25 --quiet --format json
trufflehog filesystem blindspot25 --no-verification --no-update --json --log-level=-1
gitleaks dir blindspot25 --no-banner --report-format json --report-path out.json --exit-code 0
```

## Limitations

- This report isolates the 25-file blind-spot subset only; it does not
  re-derive `comparison.md`'s full 44-file / 13/8/13 numbers (those
  stand as published, unchanged by #175's structured-config work).
- "post-#175" uses commit `7f41db7` (the third and final #175 batch);
  it was cross-checked against current `main` (`06297a7`) to confirm
  the two produce identical per-file hit results on this fixture set,
  so later unrelated commits (e.g. `#293`'s `.esmtprc` FP fix) do not
  change the headline numbers reported here.
- File-level hit counting only (a finding anywhere in the file counts),
  matching `comparison.md`'s convention — see that document's
  Limitations section for the same caveat about crediting generic vs.
  provider-specific detectors equally.
- trufflehog/gitleaks were run once each, same pinned versions
  `comparison.md` uses; both are deterministic on this fixture (no
  verification, static files), so run-to-run variance is nil.
