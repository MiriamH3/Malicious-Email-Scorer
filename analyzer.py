import re
from typing import Any


SUSPICIOUS_KEYWORDS = {
    "account": 8,
    "bank": 10,
    "click here": 10,
    "confirm": 8,
    "invoice": 6,
    "login": 8,
    "password": 12,
    "payment": 10,
    "security alert": 12,
    "suspended": 12,
    "urgent": 10,
    "verify": 10,
}

PUBLIC_EMAIL_DOMAINS = {
    "gmail.com",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "outlook.com",
    "proton.me",
    "protonmail.com",
    "walla.co.il",
    "yahoo.com",
}

ORGANIZATION_TERMS = {
    "amazon",
    "apple",
    "bank",
    "banking",
    "company",
    "facebook",
    "google",
    "hapoalim",
    "instagram",
    "leumi",
    "meta",
    "microsoft",
    "netflix",
    "paypal",
}

DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".exe",
    ".hta",
    ".js",
    ".msi",
    ".scr",
    ".vbs",
    ".zip",
}

URL_PATTERN = re.compile(r"https?://[^\s<>()\"']+", re.IGNORECASE)
EMAIL_DOMAIN_PATTERN = re.compile(r"@([^>\s]+)")


def main(payload: dict[str, Any]) -> dict[str, Any]:
    subject, sender, body, attachments = extract_email_data(payload)
    score, reasons = score_email(subject, sender, body, attachments)

    return {
        "status": "ok",
        "score": score,
        "verdict": verdict_for_score(score),
        "reasoning": format_reasoning(reasons),
        "received": {
            "subject": subject,
            "sender": sender,
            "bodyLength": len(body),
            "attachmentCount": len(attachments),
            "attachments": attachments,
        },
    }


def extract_email_data(payload: dict[str, Any]) -> tuple[str, str, str, list[dict[str, Any]]]:
    subject = to_text(payload.get("subject"))
    sender = to_text(payload.get("sender"))
    body = to_text(payload.get("body"))
    attachments = normalize_attachments(payload.get("attachments"))

    return subject, sender, body, attachments


def score_email(
    subject: str,
    sender: str,
    body: str,
    attachments: list[dict[str, Any]],
) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    combined_text = f"{subject}\n{body}".lower()

    for keyword, weight in SUSPICIOUS_KEYWORDS.items():
        if keyword in combined_text:
            score += weight
            reasons.append(f"Contains suspicious keyword or phrase: '{keyword}'.")

    urls = URL_PATTERN.findall(body)
    if urls:
        url_score = min(len(urls) * 5, 15)
        score += url_score
        reasons.append(f"Contains {len(urls)} link(s).")

    insecure_urls = find_insecure_http_urls(urls)
    if insecure_urls:
        score += min(len(insecure_urls) * 12, 24)
        reasons.append(f"Contains {len(insecure_urls)} insecure HTTP link(s).")

    if sender and not EMAIL_DOMAIN_PATTERN.search(sender):
        score += 8
        reasons.append("Sender format does not clearly expose an email domain.")

    if is_public_domain_impersonating_organization(sender, combined_text):
        score += 20
        reasons.append(
            "Sender uses a public email domain while the message references a bank or company."
        )

    attachment_score, attachment_reasons = score_attachments(attachments)
    score += attachment_score
    reasons.extend(attachment_reasons)

    score = min(score, 100)
    if not reasons:
        reasons.append("No obvious phishing indicators were detected by the current rules.")

    return score, reasons


def is_public_domain_impersonating_organization(sender: str, text: str) -> bool:
    return sender_uses_public_domain(sender) and contains_organization_terms(text)


def sender_uses_public_domain(sender: str) -> bool:
    domain = extract_sender_domain(sender)
    return domain in PUBLIC_EMAIL_DOMAINS


def extract_sender_domain(sender: str) -> str:
    match = EMAIL_DOMAIN_PATTERN.search(sender)
    if not match:
        return ""

    return match.group(1).strip(" <>.,;:").lower()


def contains_organization_terms(text: str) -> bool:
    normalized_text = text.lower()
    return any(term in normalized_text for term in ORGANIZATION_TERMS)


def find_insecure_http_urls(urls: list[str]) -> list[str]:
    return [url for url in urls if url.lower().startswith("http://")]


def score_attachments(attachments: list[dict[str, Any]]) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    if attachments:
        score += min(len(attachments) * 5, 15)
        reasons.append(f"Includes {len(attachments)} attachment(s).")

    for attachment in attachments:
        name = attachment.get("name", "").lower()
        if any(name.endswith(extension) for extension in DANGEROUS_ATTACHMENT_EXTENSIONS):
            score += 20
            reasons.append(f"Attachment has a risky file extension: {attachment.get('name')}.")

    return score, reasons


def verdict_for_score(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 35:
        return "suspicious"
    return "low_risk"


def format_reasoning(reasons: list[str]) -> str:
    return "\n".join(f"- {reason}" for reason in reasons)


def normalize_attachments(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    attachments = []
    for item in value:
        if not isinstance(item, dict):
            continue

        attachments.append(
            {
                "name": to_text(item.get("name")),
                "contentType": to_text(item.get("contentType")),
                "size": to_int(item.get("size")),
            }
        )

    return attachments


def to_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
