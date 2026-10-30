"""CTI-RAG: autonomous Cyber Threat Intelligence extraction and remediation
with a multi-agent RAG pipeline (BE project prototype, SKNCOE 2026-27).

Pipeline:  report -> Agent 1 (IOCs + behaviours) -> Agent 2 (ATT&CK mapping via ChromaDB)
           -> Agent 3 (Sigma / YARA synthesis) -> Agent 4 (pySigma / yara-python validation,
           invalid rules loop back to Agent 3 at most N times).
"""

__version__ = "0.1.0"
