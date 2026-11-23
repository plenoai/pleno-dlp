# Archive and document coverage gaps

When `pkg/archive` cannot fully expand a container, it records a
`PartialError` with a gap kind. Gaps surface as `coverage:` lines and count
toward `--fail-on-coverage`.

Whenever expansion fails or stops early, for any gap kind below, the outer
container's raw bytes are also scanned as a plain leaf, so plaintext secrets
and stored members are never hidden behind an unparseable container (#970).
This applies to every source: filesystem, git history (go-git, native, and
offline walkers), S3, GCS, docker image layers, and engine chunks. The raw
scan stays inside the source's object/artifact size budget and is not subject
to the binary-content filter; S3 and GCS objects over the 50 MiB archive
memory cap are streamed raw rather than expanded. Only bytes that never reach
pleno-dlp (over the object limit) are left unscanned.

| Kind | Meaning | Members scanned |
|---|---|---|
| `encrypted` | Password-protected member or document: ZIP/EGG encryption, HWP, Word `fEncrypted`, Excel `FILEPASS`, PowerPoint `CryptSession10Container` (RC4 / CryptoAPI). pleno-dlp does not decrypt and has no plans to, because it holds no passwords. | Other members: yes; encrypted member: no |
| `unsupported-compression` | A codec without an implementation: EGG AZO (method 3; ESTsoft's reference source forbids use in other EGG implementations, so it is not ported) and unknown methods. | Other members: yes |
| `split-volume` | One volume of a multi-volume archive scanned without its siblings (a sibling is missing, or the set exceeds the size budget, so it is not joined). EGG: the first volume yields its complete members plus the decodable prefix of the member cut at its end. Spanned zip: a `.z01` head (spanning marker, no end record) or a `.zip` terminal whose end record names disk > 0. Continuations (`.z02`…, `.002`…) with binary content. Sources emit such orphan volumes even though they are binary non-archives. | Complete members only |
| `corrupt-archive` / `corrupt-entry` | Structures that fail to parse, or declared sizes that do not match. | Members before the failure |
| `special-file`, `path` | Non-regular entries and unsafe paths. | Other members: yes |
| `max-entry-bytes`, `max-expanded-bytes`, `max-files`, `max-headers`, `max-depth` | Budget limits. | Members within the budget |

Known extraction limits that are not reported as gaps:

- PDF Type0 fonts without `/ToUnicode` decode through the Adobe character
  collection tables when the CIDs are identified: an Identity encoding with a
  registered Adobe `/CIDSystemInfo`, a predefined CJK CMap name, or an
  embedded CMap stream (including one that `/UseCMap`s a predefined CMap and
  adds local `cidchar`/`cidrange` overrides). Fonts in a non-Adobe
  collection have no Unicode mapping inside the file; their strings are
  dropped rather than emitted as glyph indices.
- PDF image filters (DCT, JPX, CCITTFax, JBIG2) and `Crypt` streams are not text and are skipped.
