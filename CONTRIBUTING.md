# Contributing

This is a team CTF writeup archive. The structure is deliberately boring so new solves can be dropped in without reorganising anything.

## Rules

1. **One challenge per folder.**
2. **Category folders are fixed:** `crypto`, `forensic`, `hardware`, `misc`, `network`, `osint`, `quantum`, `rev`, `web`. They follow the categories on the SecLeaf scoreboard.
3. **Name the solver.** Credit the teammate who solved it; use "Team Bug Busters" for joint solves.
4. **Flags are exact.** Copy the accepted value with its own prefix (`SecLeaf{...}`, `CRY{...}`, `FLOWTRIQ{...}`, or no wrapper). Don't normalise it.
5. **Preserve attachments.** Never edit or re-encode a challenge file. Derived files go in `solve/`.
6. **Solvers run from a clean checkout.** Read challenge data from `../attachments/`; no absolute paths and no network calls by default.

## Layout

```text
<category>/
└── Challenge-Name/
    ├── README.md        # brief, solver, flag, one-line insight, file index, run instructions
    ├── writeup.md       # full solve
    ├── attachments/     # exact challenge files, when archived
    └── solve/           # solver + requirements.txt (only if needed)
```

Use **Title-Case-Hyphenated** folder names with no spaces or punctuation (`Signal-and-Noise`, `TL-Priv-Escl-1`).

## What a writeup must answer, in order

1. **What is the challenge?** Restate it, and point out the hints in the name and brief.
2. **What is the data?** File shapes, fields, and which parts are noise.
3. **What is the trick?** The weakness, encoding, artefact or protocol behaviour.
4. **How do you execute it?** Commands and code a reader can follow, with the *why* before the *how*.
5. **How do you know it's correct?** The exact flag, a forward check, and any decoys ruled out.
6. **What is reusable?** Two to four lessons, not a recap of the steps.

## Solver style

- Python 3.10+, standard library first. Add `requirements.txt` only for a real dependency.
- Use `pathlib` relative to `__file__`.
- Print the intermediate values a reader needs, then a final `[+] FLAG: ...` line.
- Keep it deterministic and offline. Exploit scripts for live targets take the URL as an argument.

## When you add a challenge

- Add a row to the category `README.md` and to the root `README.md`.
- Check that the flag matches across `README.md`, `writeup.md` and the solver output.
- Check that every relative link resolves.

## Commit messages

```text
crypto: add Nonce Nursery writeup and solver
docs: update category indexes
```

## Credit and pull requests

- Name the solver in the challenge README (`Solved by`) and in the writeup (`Author`), each with a link to their GitHub profile.
- Open a pull request from a branch such as `add/<category>-<challenge-name>`; the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) holds the checklist.
- Team members are listed in [CONTRIBUTORS.md](CONTRIBUTORS.md).
