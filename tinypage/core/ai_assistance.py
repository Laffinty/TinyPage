"""AI Assistance module using OpenAI/DeepSeek API.

This module provides AI-powered writing assistance features:
- Text completion (continue writing)
- Text polishing
- Translation
- Auto summarization
- Smart tag suggestion

Uses urllib.request for HTTP calls to keep zero-dependency promise.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
import urllib.error
from typing import Optional

logger = logging.getLogger(__name__)


class AIAssistanceError(Exception):
    """Raised when AI API call fails."""
    pass


class AIAssistance:
    """AI writing assistant using OpenAI/DeepSeek compatible API."""

    def __init__(
        self,
        api_key: str = "",
        model: str = "gpt-3.5-turbo",
        provider: str = "openai",
        endpoint: str = "",
    ):
        self.api_key = api_key
        self.model = model
        self.provider = provider.lower()
        self.endpoint = endpoint or self._get_default_endpoint()

    def _get_default_endpoint(self) -> str:
        if self.provider == "deepseek":
            return "https://api.deepseek.com/v1"
        return "https://api.openai.com/v1"

    def _build_headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

    def _call_api(self, messages: list[dict], temperature: float = 0.7) -> str:
        if not self.api_key:
            raise AIAssistanceError("API key not configured")

        url = f"{self.endpoint}/chat/completions"
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers=self._build_headers(),
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode("utf-8"))
                choices = result.get("choices", [])
                if not choices:
                    raise AIAssistanceError("No response from AI")
                return choices[0].get("message", {}).get("content", "")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8") if e.fp else ""
            logger.error(f"[AI-API-ERROR] HTTP {e.code}: {body}")
            raise AIAssistanceError(f"API error: {e.code}")
        except urllib.error.URLError as e:
            logger.error(f"[AI-API-ERROR] Network error: {e.reason}")
            raise AIAssistanceError(f"Network error: {e.reason}")

    def complete_text(self, text: str, prompt_hint: str = "") -> str:
        """Continue writing from the given text.

        Args:
            text: Existing text content
            prompt_hint: Optional hint about what to write next

        Returns:
            AI-generated continuation
        """
        if not text:
            return ""

        system_prompt = "You are a helpful writing assistant. Continue the user's text naturally and coherently."
        if prompt_hint:
            system_prompt += f" The user wants to focus on: {prompt_hint}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Continue this text:\n\n{text}"},
        ]

        result = self._call_api(messages, temperature=0.8)
        return result.strip()

    def polish_text(self, text: str) -> str:
        """Polish and improve the given text.

        Args:
            text: Text to polish

        Returns:
            Polished version of the text
        """
        if not text:
            return ""

        messages = [
            {
                "role": "system",
                "content": "You are a professional editor. Improve the text for clarity, flow, and style while keeping the original meaning. Only return the improved text, no explanations.",
            },
            {
                "role": "user",
                "content": f"Polish this text:\n\n{text}",
            },
        ]

        result = self._call_api(messages, temperature=0.5)
        return result.strip()

    def translate_text(self, text: str, target_lang: str = "English") -> str:
        """Translate text to target language.

        Args:
            text: Text to translate
            target_lang: Target language name (e.g., "English", "Japanese")

        Returns:
            Translated text
        """
        if not text:
            return ""

        messages = [
            {
                "role": "system",
                "content": f"You are a professional translator. Translate the text to {target_lang} accurately and naturally. Only return the translated text, no explanations.",
            },
            {
                "role": "user",
                "content": f"Translate to {target_lang}:\n\n{text}",
            },
        ]

        result = self._call_api(messages, temperature=0.3)
        return result.strip()

    def summarize(self, text: str, max_length: int = 160) -> str:
        """Generate a summary for the given text.

        Args:
            text: Text to summarize
            max_length: Maximum summary length in characters

        Returns:
            Generated summary
        """
        if not text:
            return ""

        messages = [
            {
                "role": "system",
                "content": f"You are a content summarizer. Create a concise summary in no more than {max_length} characters. The summary should capture the main points. Only return the summary, no labels.",
            },
            {
                "role": "user",
                "content": f"Summarize this text:\n\n{text}",
            },
        ]

        result = self._call_api(messages, temperature=0.3)
        summary = result.strip()

        if len(summary) > max_length:
            summary = summary[:max_length].rsplit(" ", 1)[0] + "..."

        return summary

    def suggest_tags(self, text: str, max_tags: int = 5) -> list[str]:
        """Suggest tags based on text content.

        Args:
            text: Article content
            max_tags: Maximum number of tags to suggest

        Returns:
            List of suggested tag names
        """
        if not text:
            return []

        messages = [
            {
                "role": "system",
                "content": f"You are a content analyst. Suggest exactly {max_tags} relevant tags for this article. Tags should be short (1-3 words), lowercase, and relevant to the main topics. Return ONLY a JSON array of tag strings, like [\"python\", \"web\", \"tutorial\"]. No explanations.",
            },
            {
                "role": "user",
                "content": f"Suggest tags for:\n\n{text[:2000]}",
            },
        ]

        try:
            result = self._call_api(messages, temperature=0.3)
            result = result.strip()

            if result.startswith("```"):
                result = re.sub(r"^```(?:json)?\s*", "", result)
                result = re.sub(r"\s*```$", "", result)

            tags = json.loads(result)
            if isinstance(tags, list) and all(isinstance(t, str) for t in tags):
                return tags[:max_tags]
            return []
        except (json.JSONDecodeError, AIAssistanceError) as e:
            logger.warning(f"[AI-TAGS] Failed to get AI tags: {e}")
            return self._fallback_suggest_tags(text, max_tags)

    def _fallback_suggest_tags(self, text: str, max_tags: int = 5) -> list[str]:
        """Fallback tag suggestion using keyword extraction."""
        if not text:
            return []

        stopwords = {
            "的", "了", "是", "在", "和", "与", "或", "这", "那", "也", "都",
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "and", "or", "but", "in", "on", "at", "to", "for", "of",
            "with", "by", "from", "as", "that", "this", "it",
        }

        words = re.findall(r"[a-zA-Z\u4e00-\u9fff]{2,}", text.lower())
        word_freq: dict[str, int] = {}
        for word in words:
            if word not in stopwords and len(word) > 2:
                word_freq[word] = word_freq.get(word, 0) + 1

        sorted_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)
        tags = [word for word, _ in sorted_words[:max_tags]]

        return tags


def build_ai_assistance(config) -> Optional[AIAssistance]:
    """Build AIAssistance instance from config.

    Args:
        config: Config object with AI settings

    Returns:
        AIAssistance instance if API key is configured, None otherwise
    """
    if not getattr(config, "ai_enabled", False):
        return None
    if not getattr(config, "ai_api_key", ""):
        return None

    return AIAssistance(
        api_key=config.ai_api_key,
        model=getattr(config, "ai_model", "gpt-3.5-turbo"),
        provider=getattr(config, "ai_provider", "openai"),
        endpoint=getattr(config, "ai_endpoint", ""),
    )


def fallback_summarize(text: str, max_length: int = 160) -> str:
    """Simple fallback summary using first paragraph or first N characters.

    Args:
        text: Raw text content
        max_length: Maximum summary length

    Returns:
        Simple summary
    """
    if not text:
        return ""

    text = re.sub(r"\s+", " ", text).strip()

    first_para = text.split("\n\n")[0]
    first_para = re.sub(r"^#+\s*", "", first_para)
    first_para = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", first_para)

    if len(first_para) > max_length:
        first_para = first_para[:max_length].rsplit(" ", 1)[0] + "..."

    return first_para.strip()
