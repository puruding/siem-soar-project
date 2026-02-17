"""Inference utilities for DGA detection."""

import asyncio
import hashlib
import time
from collections import OrderedDict
from typing import Any

import torch
import torch.nn.functional as F

from common.logging import LoggerMixin
from models.dga.config import DGAConfig, DGAInferenceConfig
from models.dga.model import DGADetector, DGADetectorModel, DGAClassification, DGABatchResult
from models.dga.features import DGAFeatureExtractor, DomainTokenizer


class LRUCache:
    """Simple LRU cache for domain results."""

    def __init__(self, max_size: int = 100000, ttl_seconds: int = 3600):
        """Initialize cache.

        Args:
            max_size: Maximum cache entries
            ttl_seconds: Time-to-live in seconds
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()

    def get(self, key: str) -> Any | None:
        """Get item from cache."""
        if key not in self._cache:
            return None

        value, timestamp = self._cache[key]

        # Check TTL
        if time.time() - timestamp > self.ttl_seconds:
            del self._cache[key]
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        return value

    def set(self, key: str, value: Any) -> None:
        """Set item in cache."""
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            if len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)  # Remove oldest

        self._cache[key] = (value, time.time())

    def clear(self) -> None:
        """Clear cache."""
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


class DGAInferenceEngine(LoggerMixin):
    """High-performance inference engine for DGA detection."""

    def __init__(
        self,
        config: DGAInferenceConfig,
        model_config: DGAConfig | None = None,
    ):
        """Initialize inference engine.

        Args:
            config: Inference configuration
            model_config: Model configuration
        """
        self.config = config
        self.model_config = model_config or DGAConfig()
        self.device = torch.device(config.device)

        # Models
        self._model: DGADetectorModel | None = None
        self._tokenizer: DomainTokenizer | None = None
        self._feature_extractor: DGAFeatureExtractor | None = None

        # Cache
        self._cache: LRUCache | None = None
        if config.enable_cache:
            self._cache = LRUCache(
                max_size=config.cache_max_size,
                ttl_seconds=config.cache_ttl_seconds,
            )

        # Allowlist/Blocklist
        self._allowlist: set[str] = set()
        self._blocklist: set[str] = set()

        self._is_loaded = False

        # Metrics
        self._total_requests = 0
        self._cache_hits = 0
        self._total_latency_ms = 0.0

    async def load(self) -> None:
        """Load models and resources."""
        self.logger.info(
            "loading_inference_engine",
            model_path=self.config.model_path,
            device=str(self.device),
        )

        # Initialize tokenizer and feature extractor
        self._tokenizer = DomainTokenizer(max_length=self.model_config.max_domain_length)
        self._feature_extractor = DGAFeatureExtractor(self._tokenizer)

        # Initialize model
        self._model = DGADetectorModel(self.model_config)

        # Load weights
        try:
            checkpoint = torch.load(self.config.model_path, map_location=self.device)
            if "model_state_dict" in checkpoint:
                self._model.load_state_dict(checkpoint["model_state_dict"])
            else:
                self._model.load_state_dict(checkpoint)
            self.logger.info("model_loaded")
        except FileNotFoundError:
            self.logger.warning(
                "model_not_found",
                path=self.config.model_path,
            )
        except Exception as e:
            self.logger.error("model_load_error", error=str(e))

        self._model = self._model.to(self.device)
        self._model.eval()

        # Optional: Compile model
        if self.config.compile_model and hasattr(torch, "compile"):
            try:
                self._model = torch.compile(self._model)
                self.logger.info("model_compiled")
            except Exception as e:
                self.logger.warning("compile_failed", error=str(e))

        # Load lists
        await self._load_lists()

        self._is_loaded = True
        self.logger.info("inference_engine_loaded")

    async def _load_lists(self) -> None:
        """Load allowlist and blocklist."""
        if self.config.use_allowlist and self.config.allowlist_path:
            try:
                with open(self.config.allowlist_path) as f:
                    self._allowlist = {line.strip().lower() for line in f if line.strip()}
                self.logger.info("allowlist_loaded", count=len(self._allowlist))
            except FileNotFoundError:
                pass

        if self.config.use_blocklist and self.config.blocklist_path:
            try:
                with open(self.config.blocklist_path) as f:
                    self._blocklist = {line.strip().lower() for line in f if line.strip()}
                self.logger.info("blocklist_loaded", count=len(self._blocklist))
            except FileNotFoundError:
                pass

    def _get_cache_key(self, domain: str) -> str:
        """Generate cache key for domain."""
        return hashlib.md5(domain.lower().encode()).hexdigest()

    async def predict(self, domain: str) -> DGAClassification:
        """Predict if domain is DGA-generated.

        Args:
            domain: Domain name

        Returns:
            DGA classification result
        """
        if not self._is_loaded:
            raise RuntimeError("Engine not loaded. Call load() first.")

        start_time = time.perf_counter()
        self._total_requests += 1

        domain_clean = domain.lower().strip()

        # Check cache
        if self._cache is not None:
            cache_key = self._get_cache_key(domain_clean)
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._cache_hits += 1
                return cached

        # Check allowlist
        if domain_clean in self._allowlist:
            result = self._create_benign_result(domain, "Domain is allowlisted")
            if self._cache is not None:
                self._cache.set(cache_key, result)
            return result

        # Check blocklist
        if domain_clean in self._blocklist:
            result = self._create_dga_result(
                domain,
                confidence=1.0,
                family="unknown",
                explanation="Domain is blocklisted",
            )
            if self._cache is not None:
                self._cache.set(cache_key, result)
            return result

        # Extract features
        features = self._feature_extractor.extract_features(domain)
        tensors = self._feature_extractor.to_tensor(features, str(self.device))

        # Run inference
        with torch.no_grad():
            outputs = self._model(
                tokens=tensors["tokens"].unsqueeze(0),
                statistical_features=tensors["statistical_features"].unsqueeze(0),
            )

        # Process outputs
        probs = F.softmax(outputs["logits"], dim=-1)
        dga_prob = probs[0, 1].item()
        is_dga = dga_prob > self.config.dga_threshold

        # Get family if DGA
        family = "unknown"
        family_conf = 0.0
        if is_dga and "family_logits" in outputs:
            family_probs = F.softmax(outputs["family_logits"], dim=-1)
            family_idx = family_probs.argmax(dim=-1).item()
            family_conf = family_probs[0, family_idx].item()
            # Map index to family name
            from models.dga.config import DGAFamily
            families = list(DGAFamily)
            family = families[family_idx].value if family_idx < len(families) else "unknown"

        # Build result
        stats = features["statistics"]
        key_features = {
            "entropy": round(stats.entropy, 3),
            "length": stats.length,
            "digit_ratio": round(stats.digit_ratio, 3),
            "consonant_ratio": round(stats.consonant_ratio, 3),
        }

        result = DGAClassification(
            domain=domain,
            is_dga=is_dga,
            confidence=dga_prob,
            family=family,
            family_confidence=family_conf,
            risk_level=self._get_risk_level(dga_prob),
            features=key_features,
            explanation=self._build_explanation(domain, is_dga, dga_prob, features),
        )

        # Cache result
        if self._cache is not None:
            self._cache.set(cache_key, result)

        # Track latency
        latency_ms = (time.perf_counter() - start_time) * 1000
        self._total_latency_ms += latency_ms

        return result

    async def batch_predict(
        self,
        domains: list[str],
    ) -> DGABatchResult:
        """Predict DGA for multiple domains.

        Args:
            domains: List of domains

        Returns:
            Batch prediction results
        """
        if not self._is_loaded:
            raise RuntimeError("Engine not loaded. Call load() first.")

        start_time = time.perf_counter()
        results: list[DGAClassification] = []

        # Separate cached and uncached domains
        to_predict = []
        domain_to_idx = {}

        for i, domain in enumerate(domains):
            domain_clean = domain.lower().strip()
            cache_key = self._get_cache_key(domain_clean)

            # Check cache
            if self._cache is not None:
                cached = self._cache.get(cache_key)
                if cached is not None:
                    self._cache_hits += 1
                    results.append(cached)
                    continue

            # Check lists
            if domain_clean in self._allowlist:
                result = self._create_benign_result(domain, "Allowlisted")
                results.append(result)
                if self._cache is not None:
                    self._cache.set(cache_key, result)
                continue

            if domain_clean in self._blocklist:
                result = self._create_dga_result(domain, 1.0, "unknown", "Blocklisted")
                results.append(result)
                if self._cache is not None:
                    self._cache.set(cache_key, result)
                continue

            to_predict.append(domain)
            domain_to_idx[domain] = len(results)
            results.append(None)  # Placeholder

        # Batch predict uncached
        if to_predict:
            batch_results = await self._batch_predict_uncached(to_predict)
            for domain, result in zip(to_predict, batch_results):
                idx = domain_to_idx[domain]
                results[idx] = result

                # Cache
                if self._cache is not None:
                    cache_key = self._get_cache_key(domain.lower().strip())
                    self._cache.set(cache_key, result)

        processing_time = (time.perf_counter() - start_time) * 1000
        dga_count = sum(1 for r in results if r.is_dga)

        return DGABatchResult(
            results=results,
            total_count=len(results),
            dga_count=dga_count,
            processing_time_ms=processing_time,
        )

    async def _batch_predict_uncached(
        self,
        domains: list[str],
    ) -> list[DGAClassification]:
        """Batch predict for uncached domains."""
        results = []
        batch_size = self.config.max_batch_size

        for i in range(0, len(domains), batch_size):
            batch = domains[i : i + batch_size]

            # Extract features
            features_batch = self._feature_extractor.batch_extract(batch, str(self.device))

            # Run inference
            with torch.no_grad():
                outputs = self._model(
                    tokens=features_batch["tokens"],
                    statistical_features=features_batch["statistical_features"],
                )

            # Process outputs
            probs = F.softmax(outputs["logits"], dim=-1)
            family_probs = None
            if "family_logits" in outputs:
                family_probs = F.softmax(outputs["family_logits"], dim=-1)

            for j, domain in enumerate(batch):
                dga_prob = probs[j, 1].item()
                is_dga = dga_prob > self.config.dga_threshold

                family = "unknown"
                family_conf = 0.0
                if is_dga and family_probs is not None:
                    from models.dga.config import DGAFamily
                    families = list(DGAFamily)
                    family_idx = family_probs[j].argmax().item()
                    family_conf = family_probs[j, family_idx].item()
                    family = families[family_idx].value if family_idx < len(families) else "unknown"

                results.append(DGAClassification(
                    domain=domain,
                    is_dga=is_dga,
                    confidence=dga_prob,
                    family=family,
                    family_confidence=family_conf,
                    risk_level=self._get_risk_level(dga_prob),
                    features={},
                    explanation=f"{'DGA detected' if is_dga else 'Benign'} ({dga_prob:.1%})",
                ))

        return results

    def _create_benign_result(self, domain: str, reason: str) -> DGAClassification:
        """Create benign result."""
        return DGAClassification(
            domain=domain,
            is_dga=False,
            confidence=0.0,
            family="unknown",
            family_confidence=0.0,
            risk_level="low",
            features={},
            explanation=reason,
        )

    def _create_dga_result(
        self,
        domain: str,
        confidence: float,
        family: str,
        explanation: str,
    ) -> DGAClassification:
        """Create DGA result."""
        return DGAClassification(
            domain=domain,
            is_dga=True,
            confidence=confidence,
            family=family,
            family_confidence=0.0,
            risk_level="critical",
            features={},
            explanation=explanation,
        )

    def _get_risk_level(self, probability: float) -> str:
        """Get risk level from probability."""
        if probability >= 0.9:
            return "critical"
        elif probability >= 0.7:
            return "high"
        elif probability >= 0.5:
            return "medium"
        else:
            return "low"

    def _build_explanation(
        self,
        domain: str,
        is_dga: bool,
        confidence: float,
        features: dict[str, Any],
    ) -> str:
        """Build explanation."""
        if not is_dga:
            return f"Domain '{domain}' appears legitimate ({1-confidence:.1%} confidence)."

        stats = features["statistics"]
        indicators = []

        if stats.entropy > 3.5:
            indicators.append(f"high entropy ({stats.entropy:.2f})")
        if stats.consonant_ratio > 0.7:
            indicators.append(f"unusual consonant ratio ({stats.consonant_ratio:.0%})")
        if stats.digit_ratio > 0.3:
            indicators.append(f"high digit ratio ({stats.digit_ratio:.0%})")

        if not indicators:
            indicators.append("pattern analysis")

        return f"DGA detected ({confidence:.1%}): {', '.join(indicators)}."

    def get_metrics(self) -> dict[str, Any]:
        """Get engine metrics."""
        cache_hit_rate = (
            self._cache_hits / self._total_requests if self._total_requests > 0 else 0.0
        )
        avg_latency = (
            self._total_latency_ms / self._total_requests if self._total_requests > 0 else 0.0
        )

        return {
            "total_requests": self._total_requests,
            "cache_hits": self._cache_hits,
            "cache_hit_rate": cache_hit_rate,
            "cache_size": len(self._cache) if self._cache else 0,
            "avg_latency_ms": avg_latency,
            "allowlist_size": len(self._allowlist),
            "blocklist_size": len(self._blocklist),
        }
