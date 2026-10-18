"""Paths, environment settings and the editable model configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

REPO_ROOT = Path(os.environ.get("AEM_HOME", Path(__file__).resolve().parents[2]))
DATA_DIR = REPO_ROOT / "data"
RUNS_DIR = REPO_ROOT / "runs"
ATTACK_VERSION = "19.2"
ATTACK_FILE = DATA_DIR / "attack" / f"enterprise-attack-{ATTACK_VERSION}.json"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
ATTACK_CHECKSUMS = DATA_DIR / "attack" / "CHECKSUMS.sha256"
MODEL_CONFIG_FILE = DATA_DIR / "model_config.yaml"
SSVC_TREE_FILE = DATA_DIR / "ssvc_tree.yaml"
ORG_FILE = DATA_DIR / "org" / "fictional_org.yaml"
KNOWN_IOCS_FILE = DATA_DIR / "org" / "known_iocs_generated.yaml"
PREVALENCE_FILE = DATA_DIR / "prevalence" / "red_canary_2026.csv"
SCENARIOS_FILE = DATA_DIR / "scenarios.yaml"
BOUNDARY_PATTERNS_FILE = DATA_DIR / "boundary_patterns.yaml"
LLM_CACHE_DIR = RUNS_DIR / "llm_cache"
LLM_PRIVATE_CACHE_DIR = RUNS_DIR / "llm_cache_private"  # git-ignored: requests built from copyrighted text


class _Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CoverageConfig(_Cfg):
    partial_min: int = Field(1, ge=1, le=5)
    covered_min: int = Field(4, ge=1, le=5)
    subtechnique_policy: Literal["no_inherit", "inherit_parent"] = "no_inherit"

    @model_validator(mode="after")
    def _order(self) -> "CoverageConfig":
        if self.partial_min >= self.covered_min:
            raise ValueError("coverage.partial_min debe ser menor que coverage.covered_min")
        return self


class ExtractionConfig(_Cfg):
    chunk_max_chars: int = 100_000
    chunk_size_chars: int = 30_000
    chunk_overlap_chars: int = 2_000


class SummaryConfig(_Cfg):
    max_sentences: int = 3


class BaselineConfig(_Cfg):
    known_ioc_fraction: float = Field(0.5, gt=0, le=1)
    min_matches: int = Field(1, ge=1)
    seed: int = 20261017


class IocConfig(_Cfg):
    require_defang: bool = True
    extra_types: list[Literal["qtox", "account"]] = Field(default_factory=lambda: ["qtox", "account"])
    account_columns: list[str] = Field(default_factory=lambda: ["Username", "User Account", "Account Name"])
    qtox_min_hex: int = Field(70, ge=1, le=76)
    generic_accounts: list[str] = Field(default_factory=lambda: [
        "administrator", "admin", "root", "guest", "system", "krbtgt", "defaultaccount", "user"])
    domain_tlds: list[str] = Field(default_factory=list)
    excluded_domains: list[str] = Field(default_factory=list)


class VariantConfig(_Cfg):
    seed: int = 20261017
    require_defang: bool = True  # IoC discovery for mut; plain mentions of detected IoCs are replaced anyway (D-66)


class ExperimentConfig(_Cfg):
    replicates: int = Field(5, ge=1)
    manual_sample_size: int = Field(30, ge=1)
    sample_seed: int = 20261017


class ModelConfig(_Cfg):
    coverage: CoverageConfig = CoverageConfig()
    extraction: ExtractionConfig = ExtractionConfig()
    summary: SummaryConfig = SummaryConfig()
    baseline: BaselineConfig = BaselineConfig()
    ioc: IocConfig = IocConfig()
    variants: VariantConfig = VariantConfig()
    experiment: ExperimentConfig = ExperimentConfig()


def load_yaml(path: Path) -> dict:
    with Path(path).open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_model_config(path: Path = MODEL_CONFIG_FILE) -> ModelConfig:
    return ModelConfig.model_validate(load_yaml(path))


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str | None
    gemini_model: str
    gemini_fallback_model: str
    gemini_rpm: int
    gemini_max_retries: int

    @classmethod
    def from_env(cls, load_dotenv_file: bool = True) -> "Settings":
        if load_dotenv_file:
            from dotenv import load_dotenv

            load_dotenv(REPO_ROOT / ".env")
        return cls(
            gemini_api_key=os.environ.get("GEMINI_API_KEY") or None,
            gemini_model=os.environ.get("GEMINI_MODEL", "gemini-3.8-flash"),
            gemini_fallback_model=os.environ.get("GEMINI_FALLBACK_MODEL", "gemini-3.5-flash-lite"),
            gemini_rpm=int(os.environ.get("GEMINI_RPM", "10")),
            gemini_max_retries=int(os.environ.get("GEMINI_MAX_RETRIES", "5")),
        )
