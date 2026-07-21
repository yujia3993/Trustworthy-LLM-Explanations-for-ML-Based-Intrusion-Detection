"""Composable retrieval configurations for the Module 2 ablation ladder."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import chromadb
from rank_bm25 import BM25Okapi
from sentence_transformers import CrossEncoder, SentenceTransformer

from ..config import AMBIGUOUS_PAIR, CLASS_ORDER
from .ingest import (
    CHUNKS_SIDECAR_NAME,
    COLLECTION_NAME,
    DEFAULT_INDEX_DIR,
    load_embedding_model,
)

CROSS_ENCODER_MODEL_NAME = "cross-encoder/ms-marco-MiniLM-L-6-v2"
RRF_K = 60
RERANK_CANDIDATES = 20

# These bonuses are deliberately small in each score's native scale. They can
# resolve close candidates but cannot compensate for a materially weaker match.
DENSE_METADATA_BONUS = 0.02
RRF_METADATA_BONUS = 0.005
CROSS_ENCODER_METADATA_BONUS = 0.25

_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")

ATTACK_TYPE_DISPLAY_NAMES = {
    "benign": "benign traffic",
    "gafgyt_combo": "Gafgyt combo attack",
    "gafgyt_junk": "Gafgyt junk attack",
    "gafgyt_scan": "Gafgyt scan",
    "gafgyt_tcp": "Gafgyt TCP flood",
    "gafgyt_udp": "Gafgyt UDP flood",
    "mirai_ack": "Mirai ACK flood",
    "mirai_scan": "Mirai scan",
    "mirai_syn": "Mirai SYN flood",
    "mirai_udp": "Mirai UDP flood",
    "mirai_udpplain": "Mirai UDP plain flood",
}


@dataclass(frozen=True, slots=True)
class RetrievalConfig:
    use_bm25_rrf: bool
    use_rerank: bool
    use_decomposition: bool
    top_k: int = 5


CONFIG_DENSE = RetrievalConfig(False, False, False)
CONFIG_HYBRID = RetrievalConfig(True, False, False)
CONFIG_RERANK = RetrievalConfig(True, True, False)
CONFIG_FULL = RetrievalConfig(True, True, True)


@dataclass(frozen=True, slots=True)
class RetrievedChunk:
    chunk_id: str
    doc_id: str
    score: float
    text: str
    metadata: dict[str, Any]


def _display_name(attack_type: str) -> str:
    if attack_type not in CLASS_ORDER:
        raise ValueError(f"unknown attack type: {attack_type!r}")
    return ATTACK_TYPE_DISPLAY_NAMES[attack_type]


def build_query(
    section: str, attack_type: str, device_category: str, decomposed: bool
) -> str:
    """Construct either a generic or section-specific deterministic query."""

    attack = _display_name(attack_type)
    device = device_category.replace("_", " ")
    topic = section.replace("_", " ")
    if not decomposed:
        return f"Report {topic} guidance for a {device} involved in a {attack}."

    templates = {
        "threat_assessment": (
            f"Assess severity, botnet family context, operational risk, and victim "
            f"impact of {attack} activity from a {device}."
        ),
        "attack_mechanism": (
            f"Explain how the {attack} works, including packet generation, protocol "
            f"behaviour, targets, and resource exhaustion, for a {device}."
        ),
        "observable_indicators": (
            f"Identify observable traffic-statistics signatures of {attack} on a "
            f"{device}: packet rate, size distribution, timing, and destinations."
        ),
        "immediate_actions": (
            f"Give immediate containment and isolation steps for a {device} involved "
            f"in {attack}, including safe evidence capture and credential response."
        ),
        "longer_term_remediation": (
            f"Give longer-term hardening for a {device} after {attack}: network "
            f"segmentation, credential rotation, firmware, and exposed-service controls."
        ),
        "confidence_notes": (
            f"Explain classifier certainty, evidence limits, and appropriate confidence "
            f"language for a {attack} alert on a {device}."
        ),
    }
    if section not in templates:
        raise ValueError(f"unknown report section: {section!r}")
    if section == "confidence_notes" and attack_type in AMBIGUOUS_PAIR:
        return (
            f"Explain classifier certainty and indistinguishability for the ambiguous "
            f"Gafgyt TCP/UDP pair ({attack}) on a {device}: pair-level assertion, "
            f"missing protocol field, symmetric candidates, and calibrated abstention."
        )
    return templates[section]


def _tokenize(text: str) -> list[str]:
    return _TOKEN_PATTERN.findall(text.lower())


def _alert_family(attack_type: str) -> str:
    if attack_type.startswith("mirai_"):
        return "mirai"
    if attack_type.startswith("gafgyt_"):
        return "gafgyt"
    return "generic"


@lru_cache(maxsize=1)
def _load_cross_encoder() -> CrossEncoder:
    """Load the local reranker once per process."""

    return CrossEncoder(CROSS_ENCODER_MODEL_NAME, local_files_only=True)


class Retriever:
    """Lazy, reusable access to dense, lexical, and cross-encoder retrieval."""

    def __init__(self, persist_dir: str | Path = DEFAULT_INDEX_DIR) -> None:
        self.persist_dir = Path(persist_dir)
        self._records: list[dict[str, Any]] | None = None
        self._records_by_id: dict[str, dict[str, Any]] | None = None
        self._collection: Any | None = None
        self._dense_model: SentenceTransformer | None = None
        self._bm25: BM25Okapi | None = None
        self._cross_encoder: CrossEncoder | None = None

    @property
    def records(self) -> list[dict[str, Any]]:
        if self._records is None:
            sidecar_path = self.persist_dir / CHUNKS_SIDECAR_NAME
            if not sidecar_path.exists():
                raise FileNotFoundError(
                    f"retrieval sidecar not found at {sidecar_path}; run build_index() first"
                )
            loaded = json.loads(sidecar_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, list):
                raise ValueError(f"invalid retrieval sidecar at {sidecar_path}")
            self._records = loaded
            self._records_by_id = {record["chunk_id"]: record for record in loaded}
        return self._records

    @property
    def records_by_id(self) -> dict[str, dict[str, Any]]:
        _ = self.records
        assert self._records_by_id is not None
        return self._records_by_id

    @property
    def collection(self) -> Any:
        if self._collection is None:
            client = chromadb.PersistentClient(path=str(self.persist_dir))
            self._collection = client.get_collection(COLLECTION_NAME)
        return self._collection

    @property
    def dense_model(self) -> SentenceTransformer:
        if self._dense_model is None:
            self._dense_model = load_embedding_model()
        return self._dense_model

    @property
    def bm25(self) -> BM25Okapi:
        if self._bm25 is None:
            self._bm25 = BM25Okapi([_tokenize(record["text"]) for record in self.records])
        return self._bm25

    @property
    def cross_encoder(self) -> CrossEncoder:
        if self._cross_encoder is None:
            self._cross_encoder = _load_cross_encoder()
        return self._cross_encoder

    def _dense_ranking(self, query: str) -> list[tuple[str, float]]:
        query_embedding = self.dense_model.encode(
            [query],
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )[0]
        result = self.collection.query(
            query_embeddings=[query_embedding.tolist()],
            n_results=len(self.records),
            include=["distances"],
        )
        ids = result["ids"][0]
        distances = result["distances"][0]
        ranking = [(chunk_id, 1.0 - float(distance)) for chunk_id, distance in zip(ids, distances)]
        return sorted(ranking, key=lambda item: (-item[1], item[0]))

    def _bm25_ranking(self, query: str) -> list[tuple[str, float]]:
        scores = self.bm25.get_scores(_tokenize(query))
        ranking = [
            (record["chunk_id"], float(score))
            for record, score in zip(self.records, scores)
        ]
        return sorted(ranking, key=lambda item: (-item[1], item[0]))

    @staticmethod
    def _rrf(
        dense: list[tuple[str, float]], lexical: list[tuple[str, float]]
    ) -> list[tuple[str, float]]:
        scores: dict[str, float] = {}
        for ranking in (dense, lexical):
            for rank, (chunk_id, _) in enumerate(ranking, start=1):
                scores[chunk_id] = scores.get(chunk_id, 0.0) + 1.0 / (RRF_K + rank)
        return sorted(scores.items(), key=lambda item: (-item[1], item[0]))

    def _metadata_matches(
        self, chunk_id: str, attack_type: str, device_category: str
    ) -> int:
        record = self.records_by_id[chunk_id]
        matches = 0
        family = record["attack_family"]
        if family != "generic" and family == _alert_family(attack_type):
            matches += 1
        categories = record["device_categories"]
        if device_category in categories or "generic" in categories:
            matches += 1
        return matches

    def _apply_metadata_preference(
        self,
        ranking: list[tuple[str, float]],
        attack_type: str,
        device_category: str,
        epsilon: float,
    ) -> list[tuple[str, float]]:
        adjusted = [
            (
                chunk_id,
                score
                + epsilon
                * self._metadata_matches(chunk_id, attack_type, device_category),
            )
            for chunk_id, score in ranking
        ]
        return sorted(adjusted, key=lambda item: (-item[1], item[0]))

    def _rerank(self, query: str, candidates: list[tuple[str, float]]) -> list[tuple[str, float]]:
        candidate_ids = [chunk_id for chunk_id, _ in candidates[:RERANK_CANDIDATES]]
        pairs = [(query, self.records_by_id[chunk_id]["text"]) for chunk_id in candidate_ids]
        scores = self.cross_encoder.predict(
            pairs,
            batch_size=32,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        ranking = [(chunk_id, float(score)) for chunk_id, score in zip(candidate_ids, scores)]
        return sorted(ranking, key=lambda item: (-item[1], item[0]))

    def retrieve(
        self,
        section: str,
        attack_type: str,
        device_category: str,
        config: RetrievalConfig = CONFIG_DENSE,
    ) -> list[RetrievedChunk]:
        """Retrieve top-k chunks using the selected ablation configuration."""

        if config.top_k <= 0:
            raise ValueError("top_k must be positive")
        query = build_query(section, attack_type, device_category, config.use_decomposition)
        dense = self._dense_ranking(query)

        if config.use_bm25_rrf:
            ranking = self._rrf(dense, self._bm25_ranking(query))
            epsilon = RRF_METADATA_BONUS
        else:
            ranking = dense
            epsilon = DENSE_METADATA_BONUS

        if config.use_rerank:
            ranking = self._rerank(query, ranking)
            epsilon = CROSS_ENCODER_METADATA_BONUS

        ranking = self._apply_metadata_preference(
            ranking, attack_type, device_category, epsilon
        )
        results: list[RetrievedChunk] = []
        for chunk_id, score in ranking[: config.top_k]:
            record = self.records_by_id[chunk_id]
            metadata = {
                key: value
                for key, value in record.items()
                if key not in {"chunk_id", "doc_id", "text"}
            }
            results.append(
                RetrievedChunk(
                    chunk_id=chunk_id,
                    doc_id=record["doc_id"],
                    score=score,
                    text=record["text"],
                    metadata=metadata,
                )
            )
        return results
