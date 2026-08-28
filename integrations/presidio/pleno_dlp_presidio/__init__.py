"""pleno-dlp as a Presidio recognizer.

Runs pleno-dlp inside a Presidio AnalyzerEngine pipeline so findings
benefit from Presidio's false-positive controls: context enhancement
(LemmaContextAwareEnhancer), score_threshold, and allow_list.
"""

from .recognizer import PlenoDLPRecognizer, DEFAULT_ENTITY_MAP, build_analyzer

__all__ = ["PlenoDLPRecognizer", "DEFAULT_ENTITY_MAP", "build_analyzer"]
