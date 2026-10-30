"""Command-line interface.

    python -m ctirag doctor                 # check Python packages, Ollama, models, knowledge base
    python -m ctirag build-kb               # parse ATT&CK and index it into ChromaDB
    python -m ctirag analyze samples/report_grey_feather.txt
    python -m ctirag eval                   # pipeline vs plain-LLM baseline on samples/gold.json
    python -m ctirag serve                  # web UI on http://127.0.0.1:8000

Add --offline to any command to run without an LLM (heuristics + templates + hashed embeddings).
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

from .config import ROOT, load_config, set_offline


def _cfg(args):
    cfg = load_config(args.config)
    if args.offline:
        cfg = set_offline(cfg)
    if getattr(args, "k", None):
        cfg["pipeline"]["top_k"] = args.k
    if getattr(args, "n", None):
        cfg["pipeline"]["max_retries"] = args.n
    return cfg


def cmd_doctor(args) -> int:
    cfg = _cfg(args)
    ok = True
    print(f"Python {sys.version.split()[0]}")
    from importlib.metadata import PackageNotFoundError, version
    packages = {"chromadb": "chromadb", "sigma": "pySigma", "sigma.backends.splunk": "pySigma-backend-splunk",
                "yara": "yara-python", "fastapi": "fastapi", "uvicorn": "uvicorn", "pypdf": "pypdf",
                "requests": "requests", "yaml": "PyYAML"}
    for mod, dist in packages.items():
        try:
            importlib.import_module(mod)
            try:
                ver = version(dist)
            except PackageNotFoundError:
                ver = ""
            print(f"  [ok]  {dist} {ver}")
        except Exception as exc:  # noqa: BLE001
            ok = False
            print(f"  [!!]  {mod} missing ({exc}) -> pip install -r requirements.txt")
    print(f"LLM provider: {cfg['llm']['provider']}")
    if cfg["llm"]["provider"] == "ollama" or cfg["embeddings"]["provider"] == "ollama":
        from .llm import OllamaLLM
        health = OllamaLLM(cfg["llm"]["model"], cfg["llm"]["ollama_url"]).health()
        if not health["reachable"]:
            ok = False
            print(f"  [!!]  Ollama not reachable at {cfg['llm']['ollama_url']}: {health.get('error')}")
            print("        Install Ollama (https://ollama.com) and start it, or use --offline.")
        else:
            print(f"  [ok]  Ollama reachable at {cfg['llm']['ollama_url']}")
            needed = []
            if cfg["llm"]["provider"] == "ollama":
                needed += [cfg["llm"]["model"], cfg["llm"]["alt_model"]]
            if cfg["embeddings"]["provider"] == "ollama":
                needed.append(cfg["embeddings"]["model"])
            for model in needed:
                tag = model if ":" in model else model + ":latest"
                present = tag in health["models"] or model in health["models"]
                print(f"  [{'ok' if present else '!!'}]  model {model}" + ("" if present else f"  -> ollama pull {model}"))
                ok &= present or model == cfg["llm"]["alt_model"]
    tpath = Path(cfg["kb"]["techniques_path"])
    print(f"ATT&CK techniques file: {'found' if tpath.exists() else 'missing (build-kb will create it)'} ({tpath})")
    try:
        from .attack_kb import AttackKB
        from .embeddings import make_embedder
        kb = AttackKB(cfg, make_embedder(cfg), log=lambda *_: None)
        built = kb.is_built()
        print(f"  [{'ok' if built else '..'}]  vector store '{kb.collection_name}': "
              f"{'ready' if built else 'not built yet -> python -m ctirag build-kb' + (' --offline' if args.offline else '')}")
    except Exception as exc:  # noqa: BLE001
        print(f"  [!!]  knowledge base: {exc}")
        ok = False
    print("All good." if ok else "Some checks failed (see [!!] above).")
    return 0 if ok else 1


def cmd_build_kb(args) -> int:
    from .attack_kb import AttackKB, ensure_techniques
    from .embeddings import make_embedder
    cfg = _cfg(args)
    if args.refresh:
        ensure_techniques(cfg, refresh=True)
    kb = AttackKB(cfg, make_embedder(cfg))
    kb.build(rebuild=args.rebuild or args.refresh)
    print(f"ATT&CK v{kb.version}: {len(kb.techniques)} techniques in collection '{kb.collection_name}'")
    return 0


def _print_state(state: dict) -> None:
    s = state["stats"]
    print()
    print(f"Behaviours: {s['behaviors']} (mapped {s['behaviors_mapped']}) | techniques: {', '.join(s['techniques']) or '-'}")
    print(f"Rules: {s['rules_total']} | valid {s['rules_valid']} | fallback {s['rules_fallback']} | flagged {s['rules_flagged']}"
          f" | rejected (hallucinated) IDs: {s['rejected_ids']}")
    for b in state["behaviors"]:
        techs = ", ".join(t["id"] for t in b.get("techniques", [])) or "unmapped"
        print(f"  {b['id']:>3}  {techs:<22} {b['action'][:90]}")


def cmd_analyze(args) -> int:
    from .ingest import read_document
    from .orchestrator import Pipeline
    from .report import save_run
    cfg = _cfg(args)
    text = read_document(args.file)
    pipeline = Pipeline.from_config(cfg, use_alt_model=args.alt_model)
    state = pipeline.run(text, Path(args.file).stem)
    out = save_run(state, args.out or cfg["output_dir"])
    _print_state(state)
    print(f"\nSaved: {out}  (report.json, summary.md, rules/)")
    return 0


def cmd_eval(args) -> int:
    from .evaluate import evaluate, markdown_table
    from .orchestrator import Pipeline
    cfg = _cfg(args)
    pipeline = Pipeline.from_config(cfg, use_alt_model=args.alt_model)
    report = evaluate(pipeline, args.gold, run_baseline_too=not args.no_baseline)
    out_dir = Path(args.out or cfg["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = __import__("time").strftime("%Y%m%d-%H%M%S")
    (out_dir / f"eval-{stamp}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    table = markdown_table(report)
    (out_dir / f"eval-{stamp}.md").write_text(table + "\n", encoding="utf-8")
    print("\n" + table)
    print(f"\nSaved: {out_dir / f'eval-{stamp}.json'}")
    return 0


def cmd_serve(args) -> int:
    import uvicorn
    from .web.app import create_app
    cfg = _cfg(args)
    app = create_app(cfg, use_alt_model=args.alt_model)
    print(f"CTI-RAG UI on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ctirag", description="CTI multi-agent RAG prototype")
    ap.add_argument("--config", help="path to config.yaml (default: project root)")
    ap.add_argument("--offline", action="store_true", help="no LLM: heuristics, templates and hashed embeddings")
    ap.add_argument("--alt-model", action="store_true", help="use the alternate local model (backup plan)")
    # the same flags are accepted after the sub-command too (python -m ctirag analyze x.txt --offline)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    common.add_argument("--offline", action="store_true", default=argparse.SUPPRESS, help="run without an LLM")
    common.add_argument("--alt-model", action="store_true", default=argparse.SUPPRESS, help="use the alternate model")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="check setup", parents=[common]).set_defaults(func=cmd_doctor)

    b = sub.add_parser("build-kb", help="parse ATT&CK and build the ChromaDB index", parents=[common])
    b.add_argument("--refresh", action="store_true", help="re-download the latest ATT&CK STIX data")
    b.add_argument("--rebuild", action="store_true", help="re-embed even if the index exists")
    b.set_defaults(func=cmd_build_kb)

    a = sub.add_parser("analyze", help="run the pipeline on a report (.txt/.md/.html/.pdf)", parents=[common])
    a.add_argument("file")
    a.add_argument("--out", help="output folder (default: outputs/)")
    a.add_argument("-k", type=int, help="top-k ATT&CK entries per behaviour")
    a.add_argument("-n", type=int, help="retry cap N")
    a.set_defaults(func=cmd_analyze)

    e = sub.add_parser("eval", help="mapping accuracy and rule validity vs plain-LLM baseline", parents=[common])
    e.add_argument("--gold", default=str(ROOT / "samples" / "gold.json"))
    e.add_argument("--no-baseline", action="store_true")
    e.add_argument("--out")
    e.add_argument("-k", type=int)
    e.add_argument("-n", type=int)
    e.set_defaults(func=cmd_eval)

    s = sub.add_parser("serve", help="start the web UI", parents=[common])
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=cmd_serve)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - friendly message instead of a traceback
        from .llm import LLMError
        if isinstance(exc, LLMError):
            print(f"\nLLM problem: {exc}\nTip: run `python -m ctirag doctor`, or add --offline to run without a model.")
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
