# Benign legacy Office corpus

Regression corpus for structural false positives in OLE2 extraction (#923, #926).
None of these files contains a credential, so `TestBenignOfficeCorpusHasNoFindings`
expects zero findings.

- `test.xls`, `test.ppt`, `novpapplan.doc`, `test.msg`: from
  github.com/richardlehane/mscfb `test/` (Apache License 2.0).
- `man-ls.doc`, `man-grep.doc`: macOS `textutil -convert doc` output of the
  `ls(1)` and `grep(1)` manual pages (Word 97 binary format).
