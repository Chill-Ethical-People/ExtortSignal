from __future__ import annotations

from datetime import datetime, timezone
import json
import secrets
import time
from typing import Any
from urllib.parse import urlparse

import httpx


class AIEnrichmentError(RuntimeError):
    pass


async def probe_ai_connection(
    *,
    base_url: str,
    model: str,
    api_key: str,
    client: httpx.AsyncClient | None = None,
) -> dict[str, object]:
    """Verify authentication, model availability, inference, and JSON mode."""
    challenge = f"EXTORTSIGNAL-{secrets.token_hex(6).upper()}"
    json_challenge = f"JSON-{secrets.token_hex(5).upper()}"
    payload = {
        "model": model,
        "messages": [{
            "role": "user",
            "content": f"Connection verification. Reply with exactly this token and nothing else: {challenge}",
        }],
        "max_tokens": 32,
    }
    is_deepseek = (urlparse(base_url).hostname or "").endswith("deepseek.com")
    if is_deepseek:
        payload["thinking"] = {"type": "disabled"}

    json_payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": 'Return JSON only. Example JSON: {"challenge":"JSON-EXAMPLE","ok":true}.'},
            {"role": "user", "content": f"Return this challenge in JSON: {json_challenge}"},
        ],
        "response_format": {"type": "json_object"},
        "max_tokens": 96,
    }
    if is_deepseek:
        json_payload["thinking"] = {"type": "disabled"}

    async def send(active_client: httpx.AsyncClient) -> tuple[httpx.Response, httpx.Response, httpx.Response]:
        models_response = await active_client.get(
            f"{base_url.rstrip('/')}/models",
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        )
        completion_response = await active_client.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
        )
        json_response = await active_client.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=json_payload,
        )
        return models_response, completion_response, json_response

    started = time.perf_counter()
    try:
        if client is None:
            async with httpx.AsyncClient(timeout=20, follow_redirects=False) as active_client:
                models_response, response, json_response = await send(active_client)
        else:
            models_response, response, json_response = await send(client)
        models_response.raise_for_status()
        response.raise_for_status()
        json_response.raise_for_status()
    except httpx.HTTPStatusError as error:
        status = error.response.status_code
        if status in {401, 403}:
            message = "The provider rejected the API credential. Replace the saved key and retry."
        elif status == 404:
            message = "The provider could not find the configured endpoint or model."
        elif status == 429:
            message = "The provider rate-limited the verification request. Retry after the provider cooldown."
        else:
            message = f"The provider returned HTTP {status} during verification."
        raise AIEnrichmentError(message) from error
    except httpx.TimeoutException as error:
        raise AIEnrichmentError("The provider did not respond within 20 seconds.") from error
    except httpx.HTTPError as error:
        raise AIEnrichmentError(f"The provider connection failed: {type(error).__name__}.") from error

    latency_ms = round((time.perf_counter() - started) * 1000)
    try:
        models_body = models_response.json()
        available_models = [
            str(item["id"])
            for item in models_body.get("data", [])
            if isinstance(item, dict) and item.get("id")
        ]
        body = response.json()
        choice = body["choices"][0]
        content = choice["message"]["content"]
        json_body = json_response.json()
        json_content = json_body["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as error:
        raise AIEnrichmentError("The provider returned HTTP success but not a valid chat-completion response.") from error
    if model not in available_models:
        raise AIEnrichmentError("Authentication succeeded, but the configured model is not listed by the provider.")
    if not isinstance(content, str) or not content.strip():
        raise AIEnrichmentError("The provider returned an empty completion during verification.")
    normalized = "".join(character for character in content.upper() if character.isalnum())
    expected = "".join(character for character in challenge if character.isalnum())
    if expected not in normalized:
        raise AIEnrichmentError("The provider responded, but failed the random verification challenge.")
    structured = _parse_json_content(json_content)
    if structured.get("challenge") != json_challenge:
        raise AIEnrichmentError("Plain chat succeeded, but structured JSON verification failed.")
    return {
        "status": "verified",
        "model": model,
        "upstream_model": str(body.get("model") or model),
        "latency_ms": latency_ms,
        "response_id": str(body.get("id") or "")[:160],
        "response_preview": content.strip()[:120],
        "endpoint_host": urlparse(base_url).hostname or "local endpoint",
        "challenge_verified": True,
        "json_verified": True,
        "available_models": available_models,
        "checks": [
            {"id": "models", "label": "Authentication and model list", "status": "passed"},
            {"id": "chat", "label": "Non-thinking chat completion", "status": "passed"},
            {"id": "json", "label": "Structured JSON output", "status": "passed"},
        ],
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _parse_json_content(content: Any) -> dict:
    if isinstance(content, list):
        content = "\n".join(
            str(block.get("text", ""))
            for block in content
            if isinstance(block, dict) and block.get("text")
        )
    if not isinstance(content, str):
        raise AIEnrichmentError("AI provider returned an unsupported response")
    cleaned = content.strip().lstrip("\ufeff")
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    candidates = [cleaned]
    decoder = json.JSONDecoder()
    for index, character in enumerate(cleaned):
        if character != "{":
            continue
        try:
            decoded, _ = decoder.raw_decode(cleaned[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            candidates.append(json.dumps(decoded))
            break
    result = None
    for candidate in candidates:
        try:
            decoded = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            result = decoded
            break
    if result is None:
        raise AIEnrichmentError(
            "The AI provider responded, but no valid JSON object could be extracted. Retry once or choose a model with structured-output support."
        )
    if not isinstance(result, dict):
        raise AIEnrichmentError("AI provider returned an unsupported JSON shape")
    return result


async def request_ai_json(
    *,
    base_url: str,
    model: str,
    api_key: str,
    system_prompt: str,
    user_payload: dict,
) -> dict:
    try:
        async with httpx.AsyncClient(timeout=45, follow_redirects=False) as client:
            request_payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
                ],
                "max_tokens": 900,
            }
            if (urlparse(base_url).hostname or "").endswith("deepseek.com"):
                request_payload["thinking"] = {"type": "disabled"}
                request_payload["response_format"] = {"type": "json_object"}
            response = await client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=request_payload,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as error:
        raise AIEnrichmentError(f"AI enrichment request failed: {type(error).__name__}") from error
    return _parse_json_content(content)


def normalize_actor_analysis(result: dict) -> dict:
    def text(value: Any, limit: int) -> str:
        return " ".join(str(value or "").split())[:limit]

    try:
        confidence = int(result.get("confidence", 0))
    except (TypeError, ValueError):
        confidence = 0
    return {
        "summary": text(result.get("summary"), 900),
        "patterns": [text(item, 240) for item in result.get("patterns", []) if text(item, 240)][:5],
        "risk_observations": [text(item, 240) for item in result.get("risk_observations", []) if text(item, 240)][:5],
        "caveats": [text(item, 240) for item in result.get("caveats", []) if text(item, 240)][:4],
        "confidence": max(0, min(100, confidence)),
    }


def normalize_victim_enrichment(result: dict) -> dict:
    def text(value: Any, limit: int) -> str:
        return " ".join(str(value or "").split())[:limit]

    try:
        confidence = int(result.get("confidence", 0))
    except (TypeError, ValueError):
        confidence = 0
    return {
        "industry": text(result.get("industry"), 160),
        "country_or_region": text(result.get("country_or_region"), 120),
        "brief_description": text(result.get("brief_description"), 600),
        "organization_type": text(result.get("organization_type"), 120),
        "confidence": max(0, min(100, confidence)),
        "rationale": text(result.get("rationale"), 300),
        "source_urls": [
            text(item, 500)
            for item in result.get("source_urls", [])
            if text(item, 500)
        ][:3],
    }


def normalize_notification_draft(result: dict) -> dict:
    def text(value: Any, limit: int) -> str:
        return " ".join(str(value or "").split())[:limit]

    subject = text(result.get("subject"), 220)
    paragraphs = [
        text(item, 1800) for item in result.get("paragraphs", []) if text(item, 1800)
    ][:4]
    if not subject or len(paragraphs) != 4:
        raise AIEnrichmentError("AI provider did not return a subject and exactly four draft paragraphs")
    return {"subject": subject, "paragraphs": paragraphs}
