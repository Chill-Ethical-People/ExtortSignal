from __future__ import annotations

import os


AI_PROVIDERS = [
    {
        "id": "ollama",
        "name": "Ollama (local)",
        "region": "On this machine",
        "base_url": "http://127.0.0.1:11434/v1",
        "models": ["qwen3:1.7b", "qwen3:4b", "gemma3:4b", "qwen3:8b"],
        "api_key_env": "",
        "note": "Best privacy. Qwen3 4B is the recommended small extraction model.",
    },
    {
        "id": "deepseek",
        "name": "DeepSeek",
        "region": "Cloud · China",
        "base_url": "https://api.deepseek.com",
        "models": ["deepseek-v4-flash", "deepseek-v4-pro"],
        "api_key_env": "DEEPSEEK_API_KEY",
        "note": "Use Flash for economical classification and extraction.",
    },
    {
        "id": "kimi",
        "name": "Kimi (Moonshot AI)",
        "region": "Cloud · China / Global",
        "base_url": "https://api.moonshot.ai/v1",
        "models": ["kimi-k3", "kimi-k2.6"],
        "api_key_env": "MOONSHOT_API_KEY",
        "note": "Kimi K3 is the current flagship; K2.6 is the practical general-purpose alternative.",
    },
    {
        "id": "openai",
        "name": "OpenAI",
        "region": "Cloud · Global",
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-5.4-nano", "gpt-5.4-mini", "gpt-5.4"],
        "api_key_env": "OPENAI_API_KEY",
        "note": "Nano is the economical option for high-volume extraction and drafting.",
    },
    {
        "id": "gemini",
        "name": "Google Gemini",
        "region": "Cloud · Global",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "models": ["gemini-3.5-flash", "gemini-3.1-flash-lite", "gemini-3.1-pro-preview"],
        "api_key_env": "GEMINI_API_KEY",
        "note": "Gemini Flash is the practical default through Google's OpenAI-compatible endpoint.",
    },
    {
        "id": "dashscope",
        "name": "Alibaba Model Studio",
        "region": "Cloud · China",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "models": ["qwen-flash", "qwen-plus"],
        "api_key_env": "DASHSCOPE_API_KEY",
        "note": "Qwen Flash is the economical default; regional endpoints are also supported.",
    },
    {
        "id": "minimax",
        "name": "MiniMax",
        "region": "Cloud · China",
        "base_url": "https://api.minimax.io/v1",
        "models": ["MiniMax-M2.5", "MiniMax-M2.7"],
        "api_key_env": "MINIMAX_API_KEY",
        "note": "OpenAI-compatible cloud option for structured enrichment.",
    },
    {
        "id": "zhipu",
        "name": "GLM (Zhipu BigModel)",
        "region": "Cloud · China",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "models": ["glm-4.7-flash", "glm-5-turbo", "glm-5.2"],
        "api_key_env": "ZHIPU_API_KEY",
        "note": "GLM Flash is suited to economical classification; GLM 5.2 is the flagship option.",
    },
    {
        "id": "mistral",
        "name": "Mistral AI",
        "region": "Cloud · Europe",
        "base_url": "https://api.mistral.ai/v1",
        "models": ["mistral-small-latest", "mistral-large-latest"],
        "api_key_env": "MISTRAL_API_KEY",
        "note": "Mistral Small is the lower-cost default for extraction and concise drafting.",
    },
    {
        "id": "groq",
        "name": "GroqCloud",
        "region": "Cloud · Global",
        "base_url": "https://api.groq.com/openai/v1",
        "models": ["openai/gpt-oss-20b", "llama-3.1-8b-instant", "openai/gpt-oss-120b"],
        "api_key_env": "GROQ_API_KEY",
        "note": "Fast hosted open models; the 20B option is a sensible starting point.",
    },
    {
        "id": "openrouter",
        "name": "OpenRouter",
        "region": "Cloud · Multi-provider",
        "base_url": "https://openrouter.ai/api/v1",
        "models": ["google/gemini-3.5-flash", "openai/gpt-5.4-nano", "openai/gpt-oss-20b"],
        "api_key_env": "OPENROUTER_API_KEY",
        "note": "One API for multiple model vendors with provider routing and fallbacks.",
    },
    {
        "id": "together",
        "name": "Together AI",
        "region": "Cloud · Global",
        "base_url": "https://api.together.ai/v1",
        "models": ["openai/gpt-oss-20b", "openai/gpt-oss-120b", "MiniMaxAI/MiniMax-M2.7"],
        "api_key_env": "TOGETHER_API_KEY",
        "note": "OpenAI-compatible hosting for open-weight and partner models.",
    },
    {
        "id": "fireworks",
        "name": "Fireworks AI",
        "region": "Cloud · Global",
        "base_url": "https://api.fireworks.ai/inference/v1",
        "models": ["accounts/fireworks/models/llama-v3p2-3b-instruct", "accounts/fireworks/models/llama-v3p1-8b-instruct"],
        "api_key_env": "FIREWORKS_API_KEY",
        "note": "Economical hosted small models using an OpenAI-compatible API.",
    },
    {
        "id": "lmstudio",
        "name": "LM Studio (local)",
        "region": "On this machine",
        "base_url": "http://127.0.0.1:1234/v1",
        "models": [],
        "api_key_env": "",
        "note": "Enter the identifier of the model currently loaded in LM Studio.",
    },
    {
        "id": "vllm",
        "name": "vLLM (self-hosted)",
        "region": "Self-hosted",
        "base_url": "http://127.0.0.1:8000/v1",
        "models": [],
        "api_key_env": "",
        "note": "For a private OpenAI-compatible vLLM server; enter its served model name.",
    },
    {
        "id": "custom",
        "name": "Custom OpenAI-compatible",
        "region": "User supplied",
        "base_url": "",
        "models": [],
        "api_key_env": "OPENAI_COMPATIBLE_API_KEY",
        "note": "For another trusted provider or a self-hosted gateway.",
    },
]


def provider_catalog(stored_credentials: set[str] | None = None) -> list[dict]:
    stored_credentials = stored_credentials or set()
    return [
        {
            **provider,
            "credential_configured": (
                not provider["api_key_env"]
                or bool(os.getenv(provider["api_key_env"]))
                or provider["api_key_env"] in stored_credentials
            ),
            "credential_source": (
                "not_required" if not provider["api_key_env"]
                else "environment" if os.getenv(provider["api_key_env"])
                else "local_store" if provider["api_key_env"] in stored_credentials
                else "none"
            ),
        }
        for provider in AI_PROVIDERS
    ]


def provider_ids() -> set[str]:
    return {provider["id"] for provider in AI_PROVIDERS}


def provider_by_id(provider_id: str) -> dict | None:
    return next((provider for provider in AI_PROVIDERS if provider["id"] == provider_id), None)
