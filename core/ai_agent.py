"""Provider-flexible autonomous hunting loop for BearStrike AI."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from runtime_state import load_runtime_state, update_runtime_state
from skills_loader import build_skill_context, list_skills
from tool_registry import check_installed_tools, load_tools_config
from tool_runner import run_tool

try:
    from anthropic import Anthropic
except Exception:
    Anthropic = None  # type: ignore[assignment]


BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = BASE_DIR / "config.json"


DEFAULT_CONFIG = {
    "ai_provider": "anthropic",
    "anthropic_api_key": "your-key-here",
    "claude_model": "claude-sonnet-4-20250514",
    "openai_api_key": "",
    "openai_model": "gpt-4o-mini",
    "openai_base_url": "https://api.openai.com/v1",
    "dashboard_port": 3000,
    "mcp_port": 8888,
    "auto_hunt": True,
}


def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return dict(DEFAULT_CONFIG)

    try:
        with CONFIG_PATH.open("r", encoding="utf-8-sig") as file:
            raw = file.read().strip()
            if not raw:
                return dict(DEFAULT_CONFIG)
            data = json.loads(raw)
            merged = dict(DEFAULT_CONFIG)
            merged.update(data)
            return merged
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULT_CONFIG)


def _extract_json(text: str) -> Dict[str, Any]:
    text = text.strip()

    if text.startswith("```"):
        text = text.strip("`")
        text = text.replace("json", "", 1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "tool": "nmap",
            "target": "",
            "done": True,
            "reason": "Invalid JSON from model",
        }


def _build_system_prompt(skill_context: str, available_tools: List[str]) -> str:
    return (
        "You are BearStrike AI autonomous pentest planner.\n"
        "Follow the SKILL PLAYBOOKS first, then choose tools.\n"
        "Only choose tools from this allowlist: "
        + ", ".join(available_tools)
        + "\n"
        "Return STRICT JSON only with keys: tool, target, reason, done.\n"
        "Set done=true when no more useful action remains.\n\n"
        "SKILL PLAYBOOKS:\n"
        f"{skill_context or 'No skill documents loaded.'}"
    )


def _provider(config: Dict[str, Any]) -> str:
    return str(config.get("ai_provider", "anthropic")).strip().lower()


def _provider_model_display(config: Dict[str, Any]) -> str:
    provider = _provider(config)

    if provider == "anthropic":
        model = str(config.get("claude_model", DEFAULT_CONFIG["claude_model"])).strip()
        return f"{model} [anthropic]"

    model = str(config.get("openai_model", DEFAULT_CONFIG["openai_model"])).strip()
    return f"{model} [{provider}]"


def _provider_ready(config: Dict[str, Any]) -> bool:
    provider = _provider(config)
    if provider == "anthropic":
        key = str(config.get("anthropic_api_key", "")).strip()
        return bool(key and key != "your-key-here" and Anthropic is not None)

    if provider in {"openai", "openai_compatible", "grok", "xai"}:
        key = str(config.get("openai_api_key", "")).strip()
        return bool(key)

    return False


def _simulate_loop(target: str, available_tools: List[str]) -> None:
    print("[SIMULATION] No active AI API configured. Running local skill-driven steps.")
    update_runtime_state(current_target=target, current_task="ai-simulation")

    preferred = ["subfinder", "nmap", "whatweb", "httpx", "nuclei", "xray-suite-webscan"]
    selected = [tool for tool in preferred if tool in available_tools]

    if not selected:
        print("[AI] No installed tools available for simulation.")
        update_runtime_state(current_task="idle")
        return

    first_tool = selected[0]
    print(f"[AI] Step 1: tool={first_tool} target={target}")

    update_runtime_state(current_task=f"ai-sim running {first_tool} on {target}")
    output = run_tool(first_tool, target)

    print("[AI] Step result captured.")
    print(output[:1200])
    print("[AI] Auto hunting loop finished (simulation mode).")
    update_runtime_state(current_task="idle")


def _anthropic_decision(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> str:
    if Anthropic is None:
        raise RuntimeError("Anthropic SDK unavailable")

    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        max_tokens=512,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )

    response_text = ""
    for block in response.content:
        if getattr(block, "type", "") == "text":
            response_text += getattr(block, "text", "")
    return response_text


def _openai_compatible_decision(
    api_key: str,
    model: str,
    base_url: str,
    system_prompt: str,
    user_prompt: str,
) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 512,
    }

    request_obj = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request_obj, timeout=45) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI-compatible API error {exc.code}: {detail[:400]}") from exc

    data = json.loads(body)
    choices = data.get("choices", [])
    if not choices:
        raise RuntimeError("OpenAI-compatible API returned no choices")

    message = choices[0].get("message", {})
    return str(message.get("content", ""))


def run_auto_hunt(target: str, max_steps: int = 5) -> None:
    config = load_config()

    target = target.strip()
    if not target:
        runtime_target = str(load_runtime_state().get("current_target", "")).strip()
        target = runtime_target

    if not target:
        print("[AI] No target provided. Set target in dashboard or pass one to ai_agent.py.")
        return

    tools = load_tools_config()
    statuses = check_installed_tools()
    installed_tools = [
        str(tool.get("name", "")).strip()
        for tool in tools
        if str(tool.get("name", "")).strip() and statuses.get(str(tool.get("name", "")).strip().lower()) == "installed"
    ]

    skill_docs = list_skills()
    print(f"[AI] Loaded skills: {len(skill_docs)}")
    for skill in skill_docs:
        print(f"[AI] Skill available: {skill['name']}")

    if not installed_tools:
        print("[AI] No installed tools found. Run tool installation first.")
        return

    provider = _provider(config)
    model_display = _provider_model_display(config)

    update_runtime_state(
        current_target=target,
        ai_provider=provider,
        ai_model=model_display,
        current_task="ai-planning",
    )

    skill_context = build_skill_context(max_chars=16000)

    anthropic_key = str(config.get("anthropic_api_key", "")).strip()
    anthropic_model = str(config.get("claude_model", DEFAULT_CONFIG["claude_model"])).strip()

    openai_key = str(config.get("openai_api_key", "")).strip()
    openai_model = str(config.get("openai_model", DEFAULT_CONFIG["openai_model"])).strip()
    openai_base = str(config.get("openai_base_url", DEFAULT_CONFIG["openai_base_url"])).strip()

    if not _provider_ready(config):
        _simulate_loop(target, installed_tools)
        return

    transcript: List[Dict[str, str]] = []
    print(f"[AI] Starting BearStrike hunt on {target} with provider {provider}")

    for step in range(1, max_steps + 1):
        prompt = (
            f"Target: {target}\n"
            f"Previous transcript: {json.dumps(transcript[-4:], ensure_ascii=False)}\n"
            "Choose the next best tool step based on the loaded skills. Return JSON only."
        )

        system_prompt = _build_system_prompt(skill_context, installed_tools)

        try:
            if provider == "anthropic":
                response_text = _anthropic_decision(
                    api_key=anthropic_key,
                    model=anthropic_model,
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                )
            else:
                response_text = _openai_compatible_decision(
                    api_key=openai_key,
                    model=openai_model,
                    base_url=openai_base,
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                )
        except Exception as exc:
            print(f"[AI] Provider call failed: {exc}")
            update_runtime_state(current_task="ai-provider-failed")
            break

        decision = _extract_json(response_text)
        tool = str(decision.get("tool", "nmap")).strip() or "nmap"
        step_target = str(decision.get("target", target)).strip() or target
        reason = str(decision.get("reason", "No reason provided")).strip()
        done = bool(decision.get("done", False))

        print(f"[AI] Step {step}: tool={tool} target={step_target}")
        print(f"[AI] Reason: {reason}")

        if done:
            print("[AI] Provider marked hunt complete.")
            update_runtime_state(current_task="ai-done")
            break

        if tool not in installed_tools:
            print(f"[AI] Tool suggested but not installed: {tool}")
            transcript.append(
                {
                    "tool": tool,
                    "target": step_target,
                    "reason": reason,
                    "result": "Tool unavailable",
                }
            )
            continue

        update_runtime_state(current_target=step_target, current_task=f"ai running {tool} on {step_target}")
        result = run_tool(tool, step_target)
        transcript.append(
            {
                "tool": tool,
                "target": step_target,
                "reason": reason,
                "result": result[:2000],
            }
        )

    update_runtime_state(current_task="idle")
    print("[AI] Auto hunting loop ended.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BearStrike AI autonomous hunting agent")
    parser.add_argument("target", nargs="?", default="", help="Target domain or IP")
    parser.add_argument("--steps", type=int, default=5, help="Maximum AI loop steps")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_auto_hunt(args.target, args.steps)
