# Changelog

Built from the git history (`git log`): commit dates and short hashes are real; nothing was added by hand.
There is no release or tag yet, so no version is assigned to these changes (`pyproject.toml` declares 0.1.0,
which has not been published). Grouped by commit prefix (`feat`, `fix`, `eval`, `docs`, `chore`).

## Unreleased (up to `cdafff0`, plus the commit that adds this file)

### 2026-10-18

**Added**

- aem report --html, a self-contained results page (`cdafff0`)
- aem sensitivity for coverage thresholds (D-77) (`5d5cf1c`)
- validate manual review sheets and report indicators 4 and 5 (`8b2db31`)
- Akira anon list, private known IoCs, IoC search in check-repo (D-74, D-76) (`2996515`)
- log full 429 bodies, honour retryDelay, stop on daily quota (`58803fc`)
- eval omits a copyrighted scenario without local text and marks the run partial (`1e34e41`)
- aem report summarises a real run for the thesis (`04d2450`)
- aem suggest-anon-names proposes threat names for the anon version (`6b05dfe`)

**Fixed**

- eval_history records interrupted eval invocations too (`1a862fa`)
- quota errors stop step 4 too; document the paid Gemini tier (`37e0e27`)

**Results**

- complete run 2026-10-18-main with Akira (aggregate results only) (`5bac713`)
- real run 2026-10-18-main (Gunra and Interlock; Akira omitted, partial) (`7e69351`)

**Documentation**

- confirm fictional_org.yaml (no longer a draft) (`293eea1`)
- confirm D-03, D-11, D-20, D-21, D-30, D-31, D-41, D-62 and D-65 (`d9cab1a`)
- demo mode works from the published cache; Akira not redistributed (`a5302a5`)
- courtesy English translation of the thesis title (`fda24fc`)
- English README as primary, Spanish in README.es.md (`5eb7729`)
- D-73 confirmed (`b901925`)
- demo needs fetch-data first; repo URL in the thesis summary (`5d1b4e7`)
- repository URL in the README and citation (`6f660fe`)
- AI-use declaration in the README (`eb6ce76`)
- README lists suggest-anon-names and report; no local path in D-01 (`b15b14e`)

### 2026-10-17

**Added**

- aem check-repo scans tracked files and the whole history (`ef57f98`)
- aem preflight (OK/FALTA/AVISO) and aem eval refuses to start on FALTA (`df0cf0a`)
- anon version (mut + threat names replaced) in variants and aem eval (`944cf67`)
- label anything produced with a fake LLM as FAKE and keep it out of results/ (`b98a933`)
- report failed runs and both aggregations (valid-only, failed as 0) (`c4acb08`)
- fair IoC baseline (qTox, accounts) and leak-checked mut variants (`3312bc7`)
- evaluation metrics, experiment runner and aem eval (`7c1c3f2`)
- IoC variants (mut) and traditional IoC baseline (`8200942`)
- CISA report preparation, ATT&CK stripping and reference mappings (`2c65634`)
- output CSV, pipeline orchestration and CLI run/demo/fetch-data (`790c482`)
- step 1 extraction with code validation and analyst review; LLM summarizer for step 4 (`d1ea432`)
- Gemini client with disk cache, demo mode, rate limit and retries (`096e8f5`)
- step 4 reference consolidation, boundary patterns and prevalence template (`6011998`)
- step 3 adapted SSVC tree, analyst modes and global chain review (`cfb200c`)
- step 2 deterministic coverage analysis and draft fictional org (`56b0060`)
- ATT&CK v19.2 data access, schemas, config and verified download (`94998db`)

**Fixed**

- independent review findings in eval/ (A1-A7) and docs/REVISION_EVAL.md (`7a1471f`)
- make-variants reports an IoC leak as a clear error (`c24d76a`)
- Spanish text for the --help option (`ddc82dd`)
- clear error when a CISA advisory page changes structure (`f9876cf`)
- keep copyrighted report text out of the committed LLM cache and run outputs (`ab75a84`)

**Documentation**

- confirm D-72; D-03 verified against the v19.2 bundle (still pending) (`ea16e83`)
- runbook, README and thesis summary for anon, preflight and check-repo (`6020c4f`)
- confirm D-63, D-66, D-67, D-68, D-70; fail0 is the primary mean (`1221399`)
- runbook step for reviewing plain IoC-like tokens kept in mut (`eab17be`)
- RUNBOOK with the exact steps for the real experiments (`6399a41`)
- README, thesis methodology summary, decisions cleanup and plan log (`1d3fa26`)
- plan log block 6 (`30f6122`)
- plan log block 5 (`51200cb`)
- plan log block 4 (`9706984`)
- plan log block 3 (`cb9183e`)
- plan log block 2 (`5f4101a`)

**Maintenance**

- project skeleton, plan and decision log (`4078149`)
