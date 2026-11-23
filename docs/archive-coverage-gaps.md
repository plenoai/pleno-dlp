# Archive and document coverage gaps

When `pkg/archive` cannot fully expand a container, it records a
`PartialError` with a gap kind and, where possible, scans the raw bytes so
nothing is silently lost. Gaps surface as `coverage:` lines and count toward
`--fail-on-coverage`.

| Kind | Meaning | Raw bytes scanned |
|---|---|---|
| `encrypted` | Password-protected member or document: ZIP/EGG encryption, HWP, Word `fEncrypted`, Excel `FILEPASS`, PowerPoint `CryptSession10Container` (RC4 / CryptoAPI). pleno-dlp does not decrypt and has no plans to, because it holds no passwords. | No |
| `unsupported-compression` | A codec without an implementation: EGG AZO (method 3; ESTsoft's reference source forbids use in other EGG implementations, so it is not ported) and unknown methods. | Yes, for an unparseable archive |
| `split-volume` | An EGG split archive. Each volume arrives as its own chunk. The first volume yields its complete members plus the decodable prefix of the member cut at its end. Continuation volumes start mid-stream and cannot be decoded alone. | Continuation volumes: yes |
| `corrupt-archive` / `corrupt-entry` | Structures that fail to parse, or declared sizes that do not match. | Yes, for an unparseable archive or stream |
| `special-file`, `path` | Non-regular entries and unsafe paths. | No |
| `max-entry-bytes`, `max-expanded-bytes`, `max-files`, `max-headers`, `max-depth` | Budget limits. | No |

Known extraction limits that are not reported as gaps:

- PDF CID fonts with only a CFF program and no `/ToUnicode` (for example,
  macOS Quartz output for CJK text, ordering Adobe-Japan1) have no Unicode
  mapping inside the file. Their strings are dropped rather than emitted as
  glyph indices.
- PDF image filters (DCT, JPX, CCITTFax, JBIG2) and `Crypt` streams are not text and are skipped.
