"""pleno-dlp recognizer for Presidio.

PlenoDLPRecognizer shells out to `pleno-dlp scan stdin --format json`
and maps each JSON finding to a Presidio RecognizerResult. The Go side
emits `start`/`end` UTF-8 byte offsets of the matched secret within the
chunk; this module converts them to the character offsets Presidio
expects. The secret text itself is never transported — only positions,
so the recognizer slices spans from the caller's copy of the text.

False-positive reduction happens on the Presidio side:
  - context boost: the recognizer declares context words (token, key,
    password, ...); the AnalyzerEngine's LemmaContextAwareEnhancer
    raises scores of findings that co-occur with them.
  - score_threshold / allow_list: standard AnalyzerEngine.analyze()
    parameters filter on the verdict-derived scores below.
"""

import json
import shutil
import subprocess

try:
    from presidio_analyzer import EntityRecognizer, RecognizerResult
except ImportError:  # pragma: no cover - dependency of consumers, not tests
    from collections import namedtuple

    EntityRecognizer = object
    # Minimal stand-in so the subprocess/offset logic stays testable
    # without presidio installed.
    RecognizerResult = namedtuple(
        "RecognizerResult", ["entity_type", "start", "end", "score", "analysis_explanation"]
    )

# verdict -> score. Verified credentials are certain; unverified ones
# (provider said invalid, or verification bypassed) are still leaked
# material with the right shape, so they stay above Presidio's default
# 0 threshold but below any serious score_threshold an operator sets.
VERDICT_SCORES = {
    "verified": 1.0,
    "indeterminate": 0.5,
    "unverified": 0.3,
}
DEFAULT_SCORE = 0.5

# Curated detector-name -> Presidio entity type. Anything unmapped is
# normalized to uppercase-with-underscores from the detector name; the
# recognizer declares both in supported_entities so AnalyzerEngine
# entity filtering keeps working.
DEFAULT_ENTITY_MAP = {
    "AWS": "AWS_ACCESS_KEY",
    "GitHub": "GITHUB_TOKEN",
    "GitHubApp": "GITHUB_TOKEN",
    "GitHubFineGrained": "GITHUB_TOKEN",
    "GitLab": "GITLAB_TOKEN",
    "Slack": "SLACK_TOKEN",
    "SlackUserToken": "SLACK_TOKEN",
    "OpenAI": "OPENAI_API_KEY",
    "Anthropic": "ANTHROPIC_API_KEY",
    "GoogleOAuth": "GCP_OAUTH_TOKEN",
    "Stripe": "STRIPE_KEY",
    "SendGrid": "SENDGRID_KEY",
    "Twilio": "TWILIO_KEY",
    "PrivateKeyPEM": "PRIVATE_KEY",
    "JWT": "JWT",
    "BasicAuth": "PASSWORD",
    "HardcodedPassword": "PASSWORD",
    "Postgres": "DATABASE_CREDENTIAL",
    "MySQL": "DATABASE_CREDENTIAL",
    "MongoDBAtlas": "DATABASE_CREDENTIAL",
    "Snowflake": "DATABASE_CREDENTIAL",
}

DEFAULT_CONTEXT_WORDS = [
    "api", "key", "token", "secret", "password", "credential",
    "auth", "login", "apikey", "access", "private", "client",
]


def _normalize_entity(detector: str) -> str:
    out = []
    for ch in detector.upper():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "_":
            out.append("_")
    name = "".join(out).strip("_") or "SECRET"
    return name if len(name) <= 40 else name[:40]


def _byte_to_char_offsets(text: str, start: int, end: int):
    """Convert UTF-8 byte offsets in text to character offsets."""
    data = text.encode("utf-8")
    if start < 0 or end > len(data) or start > end:
        return None
    return (
        len(data[:start].decode("utf-8", errors="strict")),
        len(data[:end].decode("utf-8", errors="strict")),
    )


class PlenoDLPRecognizer(EntityRecognizer):
    """Recognizes leaked credentials using the pleno-dlp CLI.

    Args:
        binary: path to (or name on PATH of) the pleno-dlp executable.
        verify: pass verification through (network round-trips per
            finding). Defaults to True, matching pleno-dlp.
        entity_map: override/extend DEFAULT_ENTITY_MAP.
        timeout: subprocess timeout in seconds per analyze() call.
        extra_args: additional CLI flags (e.g. ["--only-verified"]).
    """

    def __init__(
        self,
        binary: str = "pleno-dlp",
        verify: bool = True,
        entity_map: dict | None = None,
        timeout: float = 120.0,
        extra_args: list | None = None,
        context: list | None = None,
        **kwargs,
    ):
        self._binary = shutil.which(binary) if "/" not in binary else binary
        self._verify = verify
        self._entity_map = dict(DEFAULT_ENTITY_MAP)
        if entity_map:
            self._entity_map.update(entity_map)
        self._timeout = timeout
        self._extra_args = list(extra_args or [])
        entities = sorted(
            {self._entity_map.get(k, _normalize_entity(k)) for k in self._entity_map}
            | {"GENERIC_SECRET"}
        )
        # Lazy expansion: supported_entities starts with the curated
        # set; analyze() also accepts unmapped detector names by
        # falling back to GENERIC_SECRET so filtering never drops.
        kwargs.setdefault("supported_entities", entities)
        kwargs.setdefault("name", "pleno-dlp Recognizer")
        kwargs.setdefault("context", context or DEFAULT_CONTEXT_WORDS)
        if EntityRecognizer is not object:
            super().__init__(**kwargs)

    def analyze(self, text: str, entities, nlp_artifacts=None):
        if self._binary is None:
            return []
        argv = [self._binary, "scan", "stdin", "--format", "json"]
        if not self._verify:
            argv.append("--no-verify")
        argv.extend(self._extra_args)
        try:
            # pleno-dlp exits 0 even when findings exist — stdin scans
            # never gate on findings, so stdout is pure JSON and the
            # scan summary goes to stderr.
            proc = subprocess.run(
                argv,
                input=text.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=self._timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return []
        try:
            records = json.loads(proc.stdout.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return []
        if not isinstance(records, list):
            return []

        results = []
        for rec in records:
            if "start" not in rec or "end" not in rec:
                continue  # older pleno-dlp without span offsets
            span = _byte_to_char_offsets(text, rec["start"], rec["end"])
            if span is None:
                continue
            start, end = span
            entity = self._entity_map.get(rec.get("detector"), "GENERIC_SECRET")
            if entities and entity not in entities:
                continue
            results.append(
                RecognizerResult(
                    entity_type=entity,
                    start=start,
                    end=end,
                    score=VERDICT_SCORES.get(rec.get("verdict"), DEFAULT_SCORE),
                    analysis_explanation=None,
                )
            )
        return results


def build_analyzer(binary: str = "pleno-dlp", verify: bool = True, **recognizer_kwargs):
    """Build an AnalyzerEngine with pleno-dlp plus Presidio's predefined
    recognizers. Context enhancement (LemmaContextAwareEnhancer) is on
    by default, so recognizer context words boost scores; combine with
    analyze(score_threshold=..., allow_list=[...]) for FP reduction."""
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry

    recognizer = PlenoDLPRecognizer(binary=binary, verify=verify, **recognizer_kwargs)
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()
    registry.add_recognizer(recognizer)
    return AnalyzerEngine(registry=registry)
