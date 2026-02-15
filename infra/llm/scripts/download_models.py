#!/usr/bin/env python3
"""Download and setup models for SIEM/SOAR AI services."""

import os
import sys
import logging
from pathlib import Path
from typing import Any

import yaml

try:
    from huggingface_hub import snapshot_download, login
    from huggingface_hub.utils import HfHubHTTPError
except ImportError:
    print("Installing huggingface_hub...")
    os.system("pip install huggingface_hub[cli]")
    from huggingface_hub import snapshot_download, login
    from huggingface_hub.utils import HfHubHTTPError


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# Model configurations
MODELS = {
    # LLM Models
    "solar-10.7b": {
        "repo_id": "upstage/SOLAR-10.7B-Instruct-v1.0",
        "local_dir": "/models/solar-10.7b-instruct",
        "revision": "main",
        "ignore_patterns": ["*.bin"],  # Prefer safetensors
    },
    "codellama-13b": {
        "repo_id": "codellama/CodeLlama-13b-Instruct-hf",
        "local_dir": "/models/codellama-13b-instruct",
        "revision": "main",
        "ignore_patterns": ["*.bin"],
    },
    "phi-3-mini": {
        "repo_id": "microsoft/Phi-3-mini-4k-instruct",
        "local_dir": "/models/phi-3-mini-4k-instruct",
        "revision": "main",
        "ignore_patterns": ["*.bin"],
    },
    # Embedding Models
    "bge-m3": {
        "repo_id": "BAAI/bge-m3",
        "local_dir": "/embedding_models/bge-m3",
        "revision": "main",
    },
    "ko-sroberta": {
        "repo_id": "jhgan/ko-sroberta-multitask",
        "local_dir": "/embedding_models/ko-sroberta-multitask",
        "revision": "main",
    },
    # Reranker Models
    "bge-reranker": {
        "repo_id": "BAAI/bge-reranker-v2-m3",
        "local_dir": "/embedding_models/bge-reranker-v2-m3",
        "revision": "main",
    },
}


def load_models_config(config_path: str = "/config/models.yaml") -> dict[str, Any]:
    """Load models configuration from YAML file."""
    if Path(config_path).exists():
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {}


def authenticate_hf() -> bool:
    """Authenticate with Hugging Face Hub."""
    token = os.environ.get("HF_TOKEN")
    if token:
        try:
            login(token=token)
            logger.info("Authenticated with Hugging Face Hub")
            return True
        except Exception as e:
            logger.warning(f"HF authentication failed: {e}")
    else:
        logger.info("No HF_TOKEN found, proceeding without authentication")
    return False


def download_model(
    model_name: str,
    repo_id: str,
    local_dir: str,
    revision: str = "main",
    ignore_patterns: list[str] | None = None,
) -> bool:
    """Download a model from Hugging Face Hub.

    Args:
        model_name: Friendly name for logging
        repo_id: Hugging Face repository ID
        local_dir: Local directory to save the model
        revision: Git revision to download
        ignore_patterns: File patterns to ignore

    Returns:
        True if download successful, False otherwise
    """
    local_path = Path(local_dir)

    # Check if model already exists
    if local_path.exists() and any(local_path.iterdir()):
        logger.info(f"Model {model_name} already exists at {local_dir}")
        return True

    logger.info(f"Downloading {model_name} from {repo_id}...")

    try:
        snapshot_download(
            repo_id=repo_id,
            local_dir=local_dir,
            revision=revision,
            ignore_patterns=ignore_patterns,
            resume_download=True,
            local_dir_use_symlinks=False,
        )
        logger.info(f"Successfully downloaded {model_name}")
        return True

    except HfHubHTTPError as e:
        if "401" in str(e) or "403" in str(e):
            logger.error(f"Authentication required for {model_name}. Set HF_TOKEN environment variable.")
        else:
            logger.error(f"Failed to download {model_name}: {e}")
        return False

    except Exception as e:
        logger.error(f"Failed to download {model_name}: {e}")
        return False


def download_profile(profile: str = "minimal") -> None:
    """Download models for a specific deployment profile.

    Profiles:
        minimal: Essential models only (solar-10.7b, bge-m3)
        standard: Primary + backup models
        full: All available models
    """
    config = load_models_config()

    if profile == "minimal":
        models_to_download = ["solar-10.7b", "bge-m3"]
    elif profile == "standard":
        models_to_download = ["solar-10.7b", "phi-3-mini", "bge-m3", "bge-reranker"]
    elif profile == "full":
        models_to_download = list(MODELS.keys())
    else:
        logger.error(f"Unknown profile: {profile}")
        return

    logger.info(f"Downloading models for profile: {profile}")
    logger.info(f"Models to download: {models_to_download}")

    authenticate_hf()

    success_count = 0
    for model_name in models_to_download:
        if model_name not in MODELS:
            logger.warning(f"Unknown model: {model_name}")
            continue

        model_config = MODELS[model_name]
        if download_model(
            model_name=model_name,
            repo_id=model_config["repo_id"],
            local_dir=model_config["local_dir"],
            revision=model_config.get("revision", "main"),
            ignore_patterns=model_config.get("ignore_patterns"),
        ):
            success_count += 1

    logger.info(f"Download complete: {success_count}/{len(models_to_download)} models")


def verify_models() -> dict[str, bool]:
    """Verify which models are available locally."""
    status = {}
    for model_name, config in MODELS.items():
        local_path = Path(config["local_dir"])
        exists = local_path.exists() and any(local_path.iterdir())
        status[model_name] = exists
        logger.info(f"{model_name}: {'Available' if exists else 'Not found'}")
    return status


def main() -> None:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Download models for SIEM/SOAR AI")
    parser.add_argument(
        "--profile",
        type=str,
        default="minimal",
        choices=["minimal", "standard", "full"],
        help="Deployment profile (default: minimal)"
    )
    parser.add_argument(
        "--model",
        type=str,
        help="Download a specific model by name"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify which models are available"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available models"
    )

    args = parser.parse_args()

    if args.list:
        print("\nAvailable models:")
        for name, config in MODELS.items():
            print(f"  - {name}: {config['repo_id']}")
        return

    if args.verify:
        print("\nModel verification:")
        verify_models()
        return

    if args.model:
        if args.model not in MODELS:
            print(f"Unknown model: {args.model}")
            print(f"Available: {list(MODELS.keys())}")
            sys.exit(1)

        authenticate_hf()
        config = MODELS[args.model]
        success = download_model(
            model_name=args.model,
            repo_id=config["repo_id"],
            local_dir=config["local_dir"],
            revision=config.get("revision", "main"),
            ignore_patterns=config.get("ignore_patterns"),
        )
        sys.exit(0 if success else 1)

    download_profile(args.profile)


if __name__ == "__main__":
    main()
