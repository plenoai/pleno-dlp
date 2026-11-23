Owners: detector-engineer, qa

`HardcodedPassword` no longer reports unquoted right-hand sides that are digit-free identifiers carrying a code signal (camelCase, a credential word, or a trailing `,`/`;`), such as `target.Password = appPassword` and `"app_password": appPassword,`, and resolves tuple assignments positionally so `target.Username, target.Password = "oauth2", token` attributes the literal to `Username` and emits nothing. Unquoted `.env`/INI literals such as `password=hunter2` still fire (#863).
The repo-root `.pleno-allow.json` allowlists these regression fixtures for the pre-commit hook.
