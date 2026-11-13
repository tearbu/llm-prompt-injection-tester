#!/usr/bin/env python3
"""LLM prompt-injection test harness (offline, simulated targets).

Evaluates a battery of prompt-injection test cases — aligned to the OWASP
Top 10 for LLM Applications — against a set of input-layer defenses and
simulated application responses. Each case is classified as:

  BLOCKED     an input defense stopped the payload before the model
  RESISTED    the payload reached the (simulated) app, which refused
  COMPROMISED the (simulated) app followed the injected instruction

IMPORTANT: this is an offline evaluation harness. Target responses are
bundled, fictional, pre-recorded simulations — the harness makes NO
external API calls and never talks to a real LLM. It is a framework for
structuring and scoring injection test batteries, and for regression
testing defense rulesets, not a live red-team tool.

Standard library only.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def apply_input_defenses(payload, rules):
    """Run the payload through regex-based input filters.

    Returns the name of the first matching rule, or None.
    """
    for rule in rules:
        if re.search(rule["pattern"], payload, flags=re.IGNORECASE | re.MULTILINE):
            return rule["name"]
    return None


def evaluate_case(case, rules):
    rule = apply_input_defenses(case["payload"], rules)
    if rule:
        return "BLOCKED", f"Input defense '{rule}' matched the payload"
    if case["target_outcome"] == "compromised":
        return ("COMPROMISED",
                "Payload passed input defenses; simulated app complied: "
                + case["outcome_rationale"])
    return ("RESISTED",
            "Payload passed input defenses; simulated app refused: "
            + case["outcome_rationale"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--demo", action="store_true",
                        help="run the bundled offline test battery")
    parser.add_argument("--tests", help="path to a test-cases JSON file")
    parser.add_argument("--defenses", help="path to a defenses JSON file")
    args = parser.parse_args(argv)

    base = Path(__file__).parent / "data"
    if args.demo:
        tests_path, defenses_path = base / "tests.json", base / "defenses.json"
    elif args.tests and args.defenses:
        tests_path, defenses_path = Path(args.tests), Path(args.defenses)
    else:
        parser.error("use --demo or provide both --tests and --defenses")

    cases = load_json(tests_path)
    rules = load_json(defenses_path)["pattern_rules"]

    print("=" * 74)
    print("LLM PROMPT-INJECTION TEST HARNESS — OFFLINE EVALUATION")
    print("(simulated target responses; no external API calls)")
    print("=" * 74)
    print(f"Test cases: {len(cases)}   Input defense rules: {len(rules)}")
    print()

    results = []
    for case in cases:
        verdict, rationale = evaluate_case(case, rules)
        results.append((case, verdict))
        print(f"{case['id']}  [{verdict:<11}] {case['name']}")
        print(f"         Category: {case['owasp_category']} | "
              f"Technique: {case['technique']}")
        print(f"         {rationale}")
    print()

    # --- Summary by OWASP category -----------------------------------------
    print("=" * 74)
    print("SUMMARY BY OWASP CATEGORY")
    print("=" * 74)
    by_cat = defaultdict(lambda: defaultdict(int))
    for case, verdict in results:
        by_cat[case["owasp_category"]][verdict] += 1
        by_cat[case["owasp_category"]]["total"] += 1
    for cat in sorted(by_cat):
        c = by_cat[cat]
        stopped = c["BLOCKED"] + c["RESISTED"]
        print(f"{cat}")
        print(f"  cases={c['total']}  blocked={c['BLOCKED']}  "
              f"resisted={c['RESISTED']}  compromised={c['COMPROMISED']}  "
              f"-> held {stopped}/{c['total']}")
    print()

    total = len(results)
    blocked = sum(1 for _, v in results if v == "BLOCKED")
    resisted = sum(1 for _, v in results if v == "RESISTED")
    compromised = total - blocked - resisted
    score = (blocked + resisted) / total * 100 if total else 0.0

    print("=" * 74)
    print("OVERALL RESULT")
    print("=" * 74)
    print(f"BLOCKED:     {blocked}")
    print(f"RESISTED:    {resisted}")
    print(f"COMPROMISED: {compromised}")
    print(f"Defense-effectiveness score: {score:.1f}% "
          f"({blocked + resisted}/{total} attacks did not succeed)")
    weakest = max(by_cat.items(),
                  key=lambda kv: kv[1]["COMPROMISED"] / kv[1]["total"])
    print(f"Weakest category: {weakest[0]} "
          f"({weakest[1]['COMPROMISED']}/{weakest[1]['total']} compromised)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
