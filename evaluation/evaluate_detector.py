"""Measure VeilDB's PII detector on labeled synthetic columns.

Run from the repository root with ``python -m evaluation.evaluate_detector``.
Every value is randomly generated with a fixed seed, so no real data is used and
results are reproducible. A positive means "the column is sensitive".
"""

from __future__ import annotations

import random
import string
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable

from backend.app.scanner.pii_detector import PIIDetector


SEED = 2026
REPETITIONS = 20
SAMPLES_PER_COLUMN = 10  # Matches SchemaScanner's default sample size.

FIRST = ["Aarav", "Diya", "Kabir", "Meera", "Rohan", "Sara", "Ishaan", "Anaya"]
LAST = ["Mehta", "Nair", "Shah", "Rao", "Iyer", "Khan", "Das", "Bose"]
CITIES = ["Delhi", "Pune", "Hanoi", "Rome", "Chennai", "Jaipur"]
PRODUCTS = ["Steel Bottle", "Desk Lamp", "Notebook Set", "USB Hub", "Yoga Mat"]
COMPANIES = ["Acme Traders", "Blue Harbor Ltd", "Northwind Labs", "Sunrise Foods"]

Generator = Callable[[random.Random], Any]


def digits(rng: random.Random, length: int) -> str:
    return "".join(rng.choice(string.digits) for _ in range(length))


def letters(rng: random.Random, length: int) -> str:
    return "".join(rng.choice(string.ascii_uppercase) for _ in range(length))


def calendar_date(rng: random.Random, first_year: int, last_year: int) -> str:
    return f"{rng.randint(first_year, last_year)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"


def person_name(rng: random.Random) -> str:
    return f"{rng.choice(FIRST)} {rng.choice(LAST)}"


def email(rng: random.Random) -> str:
    return f"{rng.choice(FIRST).lower()}.{rng.choice(LAST).lower()}{rng.randint(1, 999)}@example.com"


def luhn_card(rng: random.Random) -> str:
    body = "4" + digits(rng, 14)
    total = 0
    for index, digit in enumerate(int(item) for item in reversed(body)):
        doubled = digit * 2 if index % 2 == 0 else digit
        total += doubled - 9 if doubled > 9 else doubled
    return body + str((10 - total % 10) % 10)


@dataclass(frozen=True)
class SensitiveType:
    label: str
    expected: str
    descriptive_name: str
    generate: Generator


SENSITIVE_TYPES = [
    SensitiveType("email", "PII_MEDIUM", "customer_email", email),
    SensitiveType("phone", "PII_MEDIUM", "phone_number", lambda r: r.choice("6789") + digits(r, 9)),
    SensitiveType("credit card", "PII_HIGH", "credit_card", luhn_card),
    SensitiveType("aadhaar", "PII_HIGH", "aadhaar_no", lambda r: r.choice("23456789") + digits(r, 11)),
    SensitiveType("pan", "PII_HIGH", "pan_number", lambda r: letters(r, 5) + digits(r, 4) + letters(r, 1)),
    SensitiveType("ssn", "PII_HIGH", "ssn", lambda r: f"{digits(r, 3)}-{digits(r, 2)}-{digits(r, 4)}"),
    SensitiveType("bank account", "PII_HIGH", "bank_account", lambda r: digits(r, r.randint(11, 16))),
    SensitiveType("date of birth", "PII_MEDIUM", "date_of_birth", lambda r: calendar_date(r, 1960, 2005)),
    SensitiveType("salary", "FINANCIAL_CONFIDENTIAL", "salary", lambda r: round(r.uniform(30000, 200000), 2)),
    SensitiveType("person name", "PII_MEDIUM", "full_name", person_name),
    SensitiveType("passport", "PII_HIGH", "passport_number", lambda r: letters(r, 1) + digits(r, 7)),
]

NON_SENSITIVE_COLUMNS: list[tuple[str, Generator]] = [
    ("id", lambda r: r.randint(1, 100000)),
    ("order_id", lambda r: f"ORD-{digits(r, 6)}"),
    ("quantity", lambda r: r.randint(1, 40)),
    ("sku", lambda r: f"SKU-{digits(r, 4)}-{letters(r, 2)}"),
    ("city", lambda r: r.choice(CITIES)),
    ("status", lambda r: r.choice(["open", "shipped", "closed"])),
    ("created_at", lambda r: calendar_date(r, 2022, 2026)),
    ("product_name", lambda r: r.choice(PRODUCTS)),
    ("company", lambda r: r.choice(COMPANIES)),
    ("span_id", lambda r: "".join(r.choice("0123456789abcdef") for _ in range(16))),
    ("tracking_number", lambda r: digits(r, 12)),
    ("invoice_no", lambda r: r.choice("6789") + digits(r, 9)),
    ("hostname", lambda r: f"web-{r.randint(1, 9)}.internal"),
    ("filename", lambda r: f"report_{digits(r, 3)}.pdf"),
    ("zip_code", lambda r: digits(r, 6)),
    ("discount_rate", lambda r: f"{r.randint(1, 40)}.{r.randint(0, 9)}"),
]


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, actual_sensitive: bool, predicted_sensitive: bool) -> None:
        if actual_sensitive and predicted_sensitive:
            self.tp += 1
        elif actual_sensitive:
            self.fn += 1
        elif predicted_sensitive:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        total = self.precision + self.recall
        return 2 * self.precision * self.recall / total if total else 0.0


def sample(rng: random.Random, generate: Generator) -> list[Any]:
    return [generate(rng) for _ in range(SAMPLES_PER_COLUMN)]


def evaluate() -> tuple[dict[str, Score], dict[str, dict[str, list[int]]], dict[str, int]]:
    detector = PIIDetector()
    rng = random.Random(SEED)
    scores = {"descriptive names": Score(), "opaque names": Score()}
    per_type: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    false_positives: dict[str, int] = defaultdict(int)

    for _ in range(REPETITIONS):
        for scenario, score in scores.items():
            for index, kind in enumerate(SENSITIVE_TYPES):
                name = kind.descriptive_name if scenario == "descriptive names" else f"col_{index:02d}"
                result = detector.detect_column(name, sample(rng, kind.generate))
                predicted = result.classification.name
                score.add(True, predicted != "NON_SENSITIVE")
                per_type[kind.label][scenario][0] += predicted != "NON_SENSITIVE"
                per_type[kind.label][scenario][1] += predicted == kind.expected

            for index, (column, generate) in enumerate(NON_SENSITIVE_COLUMNS):
                name = column if scenario == "descriptive names" else f"col_{index + 50:02d}"
                predicted = detector.detect_column(name, sample(rng, generate)).classification.name
                score.add(False, predicted != "NON_SENSITIVE")
                if predicted != "NON_SENSITIVE":
                    false_positives[f"{column} ({scenario})"] += 1

    return scores, per_type, false_positives


def main() -> None:
    scores, per_type, false_positives = evaluate()
    print(f"Seed {SEED}, {REPETITIONS} repetitions, {SAMPLES_PER_COLUMN} samples per column\n")
    print("| Scenario | TP | FP | FN | TN | Precision | Recall | F1 |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for scenario, score in scores.items():
        print(
            f"| {scenario} | {score.tp} | {score.fp} | {score.fn} | {score.tn} | "
            f"{score.precision:.3f} | {score.recall:.3f} | {score.f1:.3f} |"
        )

    print("\n| Sensitive type | Detected, descriptive | Exact class, descriptive | Detected, opaque | Exact class, opaque |")
    print("| --- | ---: | ---: | ---: | ---: |")
    for label, results in per_type.items():
        descriptive = results["descriptive names"]
        opaque = results["opaque names"]
        print(
            f"| {label} | {descriptive[0]}/{REPETITIONS} | {descriptive[1]}/{REPETITIONS} | "
            f"{opaque[0]}/{REPETITIONS} | {opaque[1]}/{REPETITIONS} |"
        )

    print("\nFalse positives (out of 20 columns each):")
    for column, count in sorted(false_positives.items(), key=lambda item: (-item[1], item[0])):
        print(f"- {column}: {count}")


if __name__ == "__main__":
    main()
