"""Agent 4 - rule validation.

Sigma: YAML parse -> required fields -> pySigma parse -> pySigma core validators (HIGH = error)
       -> ATT&CK tags checked against the local ATT&CK list -> conversion to a Splunk query.
YARA:  compiled with yara-python.
Errors are fed back to Agent 3 by the orchestrator.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

import yaml
import yara
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as CORE_VALIDATORS

# Validators that need internet (ATT&CK / D3FEND downloads) or only make sense for a whole rule repository.
SKIPPED_VALIDATORS = {"attacktag", "d3_fendtag", "filename_length", "duplicate_filename",
                      "identifier_uniqueness", "duplicate_title", "duplicate_references"}
ATTACK_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$")


@dataclass
class ValidationResult:
    ok: bool
    rule_type: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    converted: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class RuleValidator:
    def __init__(self, kb=None):
        self.kb = kb
        self._sigma = SigmaValidator([cls for name, cls in CORE_VALIDATORS.items() if name not in SKIPPED_VALIDATORS])
        self._backend = SplunkBackend()

    def validate(self, rule_type: str, text: str) -> ValidationResult:
        return self.validate_yara(text) if rule_type == "yara" else self.validate_sigma(text)

    # ------------------------------------------------------------- Sigma
    def validate_sigma(self, text: str) -> ValidationResult:
        fail = lambda *errs: ValidationResult(False, "sigma", list(errs))  # noqa: E731
        if not (text or "").strip():
            return fail("Empty rule")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            return fail(f"YAML syntax error: {str(exc).splitlines()[0]} ({_yaml_mark(exc)})")
        if not isinstance(doc, dict):
            return fail("The rule must be a YAML mapping (key: value pairs)")
        errors = [f"Missing required field '{k}'" for k in ("title", "logsource", "detection") if k not in doc]
        det = doc.get("detection")
        if "detection" in doc and (not isinstance(det, dict) or "condition" not in det):
            errors.append("'detection' must be a mapping that contains a 'condition'")
        if errors:
            return fail(*errors)

        try:
            collection = SigmaCollection.from_yaml(text, collect_errors=True)
        except Exception as exc:  # noqa: BLE001 - any pySigma failure is a validation error
            return fail(f"pySigma could not parse the rule: {exc}")
        errors = [f"pySigma: {e}" for rule in collection.rules for e in rule.errors]
        warnings: list[str] = []
        if not errors:
            try:
                for issue in self._sigma.validate_rules(collection):
                    msg = f"{type(issue).__name__}: {issue.description}"
                    (errors if issue.severity.name == "HIGH" else warnings).append(msg)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"pySigma validators skipped: {exc}")

        for tag in doc.get("tags") or []:
            m = ATTACK_TAG.match(str(tag).strip().lower())
            if m and self.kb is not None and not self.kb.is_valid(m.group(1).upper()):
                new = self.kb.replacement(m.group(1))
                errors.append(f"ATT&CK tag '{tag}' uses technique {m.group(1).upper()}, which was revoked in "
                              f"ATT&CK v{self.kb.version}; use 'attack.{new.lower()}' instead" if new else
                              f"Unknown ATT&CK technique tag '{tag}' (not in the ATT&CK v{self.kb.version} knowledge base)")

        converted = None
        if not errors:
            try:
                out = self._backend.convert(collection)
                converted = "\n".join(map(str, out)) if isinstance(out, list) else str(out)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"Rule cannot be converted to a SIEM query (Splunk): {exc}")
        return ValidationResult(not errors, "sigma", errors, warnings, converted)

    # ------------------------------------------------------------- YARA
    def validate_yara(self, text: str) -> ValidationResult:
        if not (text or "").strip():
            return ValidationResult(False, "yara", ["Empty rule"])
        try:
            yara.compile(source=text)
        except yara.SyntaxError as exc:
            return ValidationResult(False, "yara", [f"YARA syntax error: {exc}"])
        except yara.Error as exc:
            return ValidationResult(False, "yara", [f"YARA error: {exc}"])
        warnings = [] if ("strings:" in text or "hash." in text) else ["Rule has no strings or hash conditions"]
        return ValidationResult(True, "yara", [], warnings, None)


def _yaml_mark(exc: Exception) -> str:
    mark = getattr(exc, "problem_mark", None)
    return f"line {mark.line + 1}, column {mark.column + 1}" if mark else "unknown position"
