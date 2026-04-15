#!/usr/bin/env python3
"""
VulnScan AI Engine — LangChain-powered vulnerability analysis.
This module can be used standalone or called by the Rust backend.
"""

import json
import sys
import os
from typing import Optional

# LangChain imports — install via: pip install langchain langchain-openai langchain-anthropic
try:
    from langchain.schema import HumanMessage, SystemMessage
    from langchain.prompts import PromptTemplate
    from langchain.chains import LLMChain
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

SYSTEM_PROMPT = """You are an expert penetration tester and cybersecurity analyst with 15+ years of experience.
Your task is to analyze vulnerability scan results and produce a comprehensive, actionable security report.

Guidelines:
- Be precise and technical but accessible
- Prioritize findings by actual risk, not just CVSS scores
- Provide specific, actionable remediation steps
- Reference relevant CVEs, CWEs, and security standards (OWASP, NIST)
- Consider attack chaining and combined risk scenarios
- Include evidence-based reasoning for severity ratings

Always respond with valid JSON only."""

ANALYSIS_TEMPLATE = """Analyze the following vulnerability scan results for {target} and produce a comprehensive security assessment.

SCAN TYPE: {scan_type}
SCAN DATE: {scan_date}
RAW FINDINGS:
{findings_json}

Return a JSON object with:
{{
  "risk_score": <number 0-100>,
  "overall_risk": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "executive_summary": "<2-3 paragraph executive summary>",
  "attack_scenarios": [
    {{"title": "...", "description": "...", "likelihood": "HIGH|MEDIUM|LOW"}}
  ],
  "enhanced_findings": [
    {{
      "id": "...",
      "severity": "...",
      "title": "...", 
      "description": "...",
      "port": null,
      "service": null,
      "cve": ["CVE-XXXX-XXXXX"],
      "cvss_score": 0.0,
      "recommendation": "...",
      "evidence": "..."
    }}
  ],
  "remediation_roadmap": {{
    "immediate": ["..."],
    "short_term": ["..."],
    "long_term": ["..."]
  }},
  "report": "<full markdown report>"
}}"""


def get_llm(provider: str, model: str, api_key: str, base_url: Optional[str] = None):
    """Get LangChain LLM based on provider."""
    
    if not LANGCHAIN_AVAILABLE:
        raise ImportError("LangChain not installed. Run: pip install langchain")
    
    if provider == "openai":
        from langchain_openai import ChatOpenAI
        kwargs = {"model": model, "api_key": api_key, "temperature": 0.1}
        if base_url:
            kwargs["base_url"] = base_url
        return ChatOpenAI(**kwargs)
    
    elif provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=model, api_key=api_key, temperature=0.1)
    
    elif provider == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(model=model, api_key=api_key, temperature=0.1)
    
    elif provider == "together":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url="https://api.together.xyz/v1",
            temperature=0.1
        )
    
    elif provider == "openrouter":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            temperature=0.1
        )
    
    elif provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=model,
            base_url=base_url or "http://localhost:11434",
            temperature=0.1
        )
    
    else:
        # Generic OpenAI-compatible
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url=base_url or "https://api.openai.com/v1",
            temperature=0.1
        )


def analyze_findings(
    provider: str,
    model: str, 
    api_key: str,
    target: str,
    scan_type: str,
    findings: list,
    base_url: Optional[str] = None
) -> dict:
    """
    Use LangChain to analyze vulnerability findings and generate a report.
    """
    from datetime import datetime
    
    llm = get_llm(provider, model, api_key, base_url)
    
    prompt = ANALYSIS_TEMPLATE.format(
        target=target,
        scan_type=scan_type,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        findings_json=json.dumps(findings, indent=2)
    )
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=prompt)
    ]
    
    response = llm.invoke(messages)
    content = response.content
    
    # Clean JSON if wrapped in markdown code blocks
    if "```json" in content:
        content = content.split("```json")[1].split("```")[0].strip()
    elif "```" in content:
        content = content.split("```")[1].split("```")[0].strip()
    
    return json.loads(content)


def generate_report_markdown(analysis: dict, target: str, scan_type: str) -> str:
    """Generate a formatted markdown report from AI analysis."""
    
    if "report" in analysis and analysis["report"]:
        return analysis["report"]
    
    findings = analysis.get("enhanced_findings", [])
    roadmap = analysis.get("remediation_roadmap", {})
    scenarios = analysis.get("attack_scenarios", [])
    
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    
    md = f"""# Security Vulnerability Assessment Report

**Target:** {target}  
**Scan Type:** {scan_type}  
**Date:** {now}  
**Overall Risk:** {analysis.get('overall_risk', 'UNKNOWN')}  
**Risk Score:** {analysis.get('risk_score', 0)}/100  

---

## Executive Summary

{analysis.get('executive_summary', 'No summary available.')}

---

## Finding Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {sum(1 for f in findings if f.get('severity','').upper() == 'CRITICAL')} |
| 🟠 High | {sum(1 for f in findings if f.get('severity','').upper() == 'HIGH')} |
| 🟡 Medium | {sum(1 for f in findings if f.get('severity','').upper() == 'MEDIUM')} |
| 🟢 Low | {sum(1 for f in findings if f.get('severity','').upper() == 'LOW')} |
| ℹ️ Info | {sum(1 for f in findings if f.get('severity','').upper() == 'INFO')} |

---

## Attack Scenarios

"""
    
    for s in scenarios:
        md += f"### {s.get('title', 'Unnamed Scenario')}\n\n"
        md += f"**Likelihood:** {s.get('likelihood', 'Unknown')}\n\n"
        md += f"{s.get('description', '')}\n\n"
    
    md += "---\n\n## Detailed Findings\n\n"
    
    for i, f in enumerate(findings, 1):
        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(
            f.get('severity', '').lower(), "⚪"
        )
        md += f"### {i}. {sev_icon} {f.get('title', 'Unnamed Finding')}\n\n"
        md += f"**Severity:** {f.get('severity', 'Unknown')}"
        if f.get('cvss_score'):
            md += f" (CVSS: {f['cvss_score']})"
        md += "\n"
        if f.get('port'):
            md += f"**Port/Service:** {f['port']}/{f.get('service', 'unknown')}\n"
        if f.get('cve'):
            md += f"**CVE:** {', '.join(f['cve'])}\n"
        md += f"\n**Description:**\n{f.get('description', '')}\n\n"
        md += f"**Evidence:**\n```\n{f.get('evidence', 'N/A')}\n```\n\n"
        md += f"**Recommendation:**\n{f.get('recommendation', 'No recommendation provided.')}\n\n---\n\n"
    
    md += "## Remediation Roadmap\n\n"
    
    if roadmap.get('immediate'):
        md += "### 🚨 Immediate (0-7 days)\n\n"
        for item in roadmap['immediate']:
            md += f"- {item}\n"
        md += "\n"
    
    if roadmap.get('short_term'):
        md += "### ⚡ Short-term (7-30 days)\n\n"
        for item in roadmap['short_term']:
            md += f"- {item}\n"
        md += "\n"
    
    if roadmap.get('long_term'):
        md += "### 📋 Long-term (30-90 days)\n\n"
        for item in roadmap['long_term']:
            md += f"- {item}\n"
        md += "\n"
    
    md += f"\n---\n\n*Report generated by VulnScan AI Engine using LangChain · {now}*\n"
    
    return md


# CLI entrypoint for standalone use
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ai_engine.py <config.json>")
        sys.exit(1)
    
    with open(sys.argv[1]) as f:
        cfg = json.load(f)
    
    result = analyze_findings(
        provider=cfg["provider"],
        model=cfg["model"],
        api_key=cfg["api_key"],
        target=cfg["target"],
        scan_type=cfg["scan_type"],
        findings=cfg["findings"],
        base_url=cfg.get("base_url")
    )
    
    report = generate_report_markdown(result, cfg["target"], cfg["scan_type"])
    print(report)
