# Archive and document coverage gaps

When `pkg/archive` cannot fully expand a container, it records a
`PartialError` with a gap kind and, where possible, scans the raw bytes so
nothing is silently lost. Gaps surface as `coverage:` lines and count toward
`--fail-on-coverage`.

| Kind | Meaning | Raw bytes scanned |
|---|---|---|
| `encrypted` | Password-protected member or document: ZIP/EGG encryption, HWP, Word `fEncrypted`, Excel `FILEPASS`, PowerPoint `CryptSession10Container` (RC4 / CryptoAPI). pleno-dlp does not decrypt and has no plans to, because it holds no passwords. | No |
| `unsupported-compression` | A codec without an implementation: EGG AZO (method 3; ESTsoft's reference source forbids use in other EGG implementations, so it is not ported) and unknown methods. | Yes, for an unparseable archive |
| `split-volume` | One volume of a multi-volume archive scanned without its siblings (a sibling is missing, or the set exceeds the size budget, so it is not joined). EGG: the first volume yields its complete members plus the decodable prefix of the member cut at its end. Spanned zip: a `.z01` head (spanning marker, no end record) or a `.zip` terminal whose end record names disk > 0. Continuations (`.z02`…, `.002`…) with binary content. Sources emit such orphan volumes even though they are binary non-archives. | Continuation volumes: yes |
| `corrupt-archive` / `corrupt-entry` | Structures that fail to parse, or declared sizes that do not match. | Yes, for an unparseable archive or stream |
| `special-file`, `path` | Non-regular entries and unsafe paths. | No |
| `max-entry-bytes`, `max-expanded-bytes`, `max-files`, `max-headers`, `max-depth` | Budget limits. | No |

Known extraction limits that are not reported as gaps:

- PDF CID fonts with only a CFF program and no `/ToUnicode` (for example,
  macOS Quartz output for CJK text, ordering Adobe-Japan1) have no Unicode
  mapping inside the file. Their strings are dropped rather than emitted as
  glyph indices.
- PDF image filters (DCT, JPX, CCITTFax, JBIG2) and `Crypt` streams are not text and are skipped.
