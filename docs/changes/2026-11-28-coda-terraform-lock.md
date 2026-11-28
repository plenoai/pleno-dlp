Owners: detector-engineer, qa

Stop the Coda detector from flagging `.terraform.lock.hcl` `h1:` checksums as
tokens: candidates inside an `h1:`/`zh:` value are skipped, and a `coda`
keyword embedded in a longer alnum run (such as `cOda` inside base64) no longer
counts as context (HikaruEgashira/iac-aws#1074).
