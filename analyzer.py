import difflib
import ipaddress
import re
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse


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

BODY_LOW_SIGNAL_KEYWORDS = {
    "account",
    "bank",
    "payment",
}

URGENCY_KEYWORDS = {
    "suspended",
    "urgent",
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

POPULAR_BRAND_DOMAINS = [
    "apple",
    "bankleumi",
    "google",
    "microsoft",
    "paypal",
]

URL_SHORTENERS = {
    "bit.ly",
    "rebrand.ly",
    "t.co",
    "tinyurl.com",
}

NUMBER_SUBSTITUTIONS = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
    }
)

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

COMMON_ATTACHMENT_EXTENSIONS = {
    ".doc",
    ".docx",
    ".gif",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".txt",
    ".xls",
    ".xlsx",
}

URL_PATTERN = re.compile(r"https?://[^\s<>()\"']+", re.IGNORECASE)
EMAIL_DOMAIN_PATTERN = re.compile(r"@([^>\s]+)")
HIDDEN_EXTENSION_SPACES_PATTERN = re.compile(r"\s{5,}\.[^.\\/\s]+$")


def main(payload: dict[str, Any]) -> dict[str, Any]:
    email = normalize_payload(payload)
    score, reasons = score_email(
        email["subject"],
        email["sender"],
        email["body"],
        email["links"],
        email["attachments"],
    )

    return {
        "status": "ok",
        "score": score,
        "verdict": verdict_for_score(score),
        "reasoning": format_reasoning(reasons),
        "received": {
            "subject": email["subject"],
            "sender": email["sender"],
            "bodyLength": len(email["body"]),
            "linkCount": len(email["links"]),
            "links": email["links"],
            "attachmentCount": len(email["attachments"]),
            "attachments": email["attachments"],
        },
    }


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    def as_text(value: Any) -> str:
        return "" if value is None else str(value)

    def as_int(value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    raw_links = payload.get("links")
    raw_attachments = payload.get("attachments")

    return {
        "subject": as_text(payload.get("subject")),
        "sender": as_text(payload.get("sender")),
        "body": as_text(payload.get("body")),
        "links": [
            {
                "url": as_text(item.get("url")).strip(),
                "text": as_text(item.get("text")).strip(),
            }
            for item in raw_links
            if isinstance(item, dict)
        ]
        if isinstance(raw_links, list)
        else [],
        "attachments": [
            {
                "name": as_text(item.get("name")),
                "contentType": as_text(item.get("contentType")),
                "size": as_int(item.get("size")),
            }
            for item in raw_attachments
            if isinstance(item, dict)
        ]
        if isinstance(raw_attachments, list)
        else [],
    }


def score_email(
    subject: str,
    sender: str,
    body: str,
    links: list[dict[str, Any]],
    attachments: list[dict[str, Any]],
) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    combined_text = f"{subject}\n{body}".lower()

    keyword_score, keyword_reasons = score_keyword_signals(subject, body)
    score += keyword_score
    reasons.extend(keyword_reasons)

    urls, url_score, url_reasons = score_urls(body, links)
    score += url_score
    reasons.extend(url_reasons)

    if has_urgency_signal(subject, body) and urls:
        score += 30
        reasons.append("Combines urgency language with link(s), increasing phishing risk.")

    if sender and not EMAIL_DOMAIN_PATTERN.search(sender):
        score += 8
        reasons.append("Sender format does not clearly expose an email domain.")

    if is_public_domain_impersonating_organization(sender, combined_text):
        score += 20
        reasons.append(
            "Sender uses a public email domain while the message references a bank or company."
        )

    display_name_score, display_name_reasons = score_display_name_spoofing(sender)
    score += display_name_score
    reasons.extend(display_name_reasons)

    typosquatting_score, typosquatting_reasons = score_sender_typosquatting(sender)
    score += typosquatting_score
    reasons.extend(typosquatting_reasons)

    attachment_score, attachment_reasons = score_attachments(attachments)
    score += attachment_score
    reasons.extend(attachment_reasons)

    score = min(score, 100)
    if not reasons:
        reasons.append("No obvious phishing indicators were detected by the current rules.")

    return score, reasons


def score_keyword_signals(subject: str, body: str) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    subject_text = subject.lower()
    body_text = body.lower()

    for keyword, weight in SUSPICIOUS_KEYWORDS.items():
        if keyword in subject_text:
            keyword_score = weight * 2
            score += keyword_score
            reasons.append(
                f"Subject contains suspicious keyword or phrase: '{keyword}'."
            )
            continue

        if keyword not in body_text:
            continue

        keyword_score = 2 if keyword in BODY_LOW_SIGNAL_KEYWORDS else weight
        score += keyword_score
        if keyword in BODY_LOW_SIGNAL_KEYWORDS:
            reasons.append(
                f"Body contains common financial keyword '{keyword}' with reduced weight."
            )
        else:
            reasons.append(f"Body contains suspicious keyword or phrase: '{keyword}'.")

    return score, reasons


def has_urgency_signal(subject: str, body: str) -> bool:
    combined_text = f"{subject}\n{body}".lower()
    return any(keyword in combined_text for keyword in URGENCY_KEYWORDS)


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


def score_display_name_spoofing(sender: str) -> tuple[int, list[str]]:
    display_name = extract_sender_display_name(sender)
    if not display_name or not sender_uses_public_domain(sender):
        return 0, []

    if not contains_organization_terms(display_name):
        return 0, []

    domain = extract_sender_domain(sender)
    return 60, [
        f"Sender display name '{display_name}' references an organization while using public domain '{domain}'."
    ]


def extract_sender_display_name(sender: str) -> str:
    display_name, email_address = parseaddr(sender)
    if display_name:
        return display_name.strip().strip("\"'")

    if email_address and email_address != sender:
        return ""

    if "<" in sender:
        return sender.split("<", 1)[0].strip().strip("\"'")

    return ""


def collect_urls(body: str, links: list[dict[str, Any]]) -> list[str]:
    urls = URL_PATTERN.findall(body) + [
        link["url"] for link in links if URL_PATTERN.match(link["url"])
    ]
    return list(dict.fromkeys(url.strip() for url in urls if url.strip()))


def score_urls(body: str, links: list[dict[str, Any]]) -> tuple[list[str], int, list[str]]:
    urls = collect_urls(body, links)
    if not urls:
        return urls, 0, []

    insecure_count = 0
    direct_ip_count = 0
    shortener_hosts = set()

    for url in urls:
        parsed_url = urlparse(url)
        hostname = (parsed_url.hostname or "").lower()
        normalized_hostname = hostname.removeprefix("www.")

        insecure_count += url.lower().startswith("http://")
        if normalized_hostname in URL_SHORTENERS:
            shortener_hosts.add(hostname)

        try:
            if hostname:
                ipaddress.ip_address(hostname)
                direct_ip_count += 1
        except ValueError:
            pass

    score = min(len(urls) * 5, 15)
    reasons = [f"Contains {len(urls)} link(s)."]

    if insecure_count:
        score += min(insecure_count * 12, 24)
        reasons.append(f"Contains {insecure_count} insecure HTTP link(s).")

    if shortener_hosts:
        score += 35
        reasons.append(
            "Contains URL shortener link(s): "
            + ", ".join(sorted(shortener_hosts))
            + "."
        )

    if direct_ip_count:
        score += 60
        reasons.append(f"Contains {direct_ip_count} link(s) that use a direct IP address.")

    return urls, score, reasons


def score_sender_typosquatting(sender: str) -> tuple[int, list[str]]:
    domain_label = extract_sender_domain_label(sender)
    if not domain_label:
        return 0, []

    score = 0
    reasons = []

    if domain_uses_number_substitution(domain_label):
        score += 40
        reasons.append(
            f"Sender domain '{domain_label}' appears to use numbers instead of letters."
        )

    similar_domain = find_similar_popular_domain(domain_label)
    if similar_domain:
        score += 50
        reasons.append(
            f"Sender domain '{domain_label}' is similar to popular domain '{similar_domain}'."
        )

    return score, reasons


def extract_sender_domain_label(sender: str) -> str:
    domain = extract_sender_domain(sender)
    if not domain:
        return ""

    return domain.split(".")[0]


def domain_uses_number_substitution(domain_label: str) -> bool:
    if not any(character.isdigit() for character in domain_label):
        return False

    normalized_domain = domain_label.translate(NUMBER_SUBSTITUTIONS)
    return any(
        difflib.SequenceMatcher(None, normalized_domain, popular_domain).ratio() >= 0.8
        for popular_domain in POPULAR_BRAND_DOMAINS
    )


def find_similar_popular_domain(domain_label: str) -> str:
    if domain_label in POPULAR_BRAND_DOMAINS:
        return ""

    for popular_domain in POPULAR_BRAND_DOMAINS:
        similarity = difflib.SequenceMatcher(None, domain_label, popular_domain).ratio()
        if similarity >= 0.8:
            return popular_domain

    return ""


def score_attachments(attachments: list[dict[str, Any]]) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    if attachments:
        score += min(len(attachments) * 5, 15)
        reasons.append(f"Includes {len(attachments)} attachment(s).")

    for attachment in attachments:
        original_name = attachment.get("name", "")
        name = original_name.lower()
        checks = [
            (
                has_double_extension(name),
                50,
                f"Attachment has a double extension, which can hide the real file type: {original_name}.",
            ),
            (
                has_hidden_extension_spacing(original_name),
                30,
                f"Attachment uses many spaces before the extension, which can hide the real file type: {original_name}.",
            ),
            (
                any(name.endswith(extension) for extension in DANGEROUS_ATTACHMENT_EXTENSIONS),
                20,
                f"Attachment has a risky file extension: {original_name}.",
            ),
        ]

        for matched, weight, reason in checks:
            if matched:
                score += weight
                reasons.append(reason)

    return score, reasons


def has_double_extension(filename: str) -> bool:
    extension_parts = get_filename_extension_parts(filename)
    if len(extension_parts) < 2:
        return False

    previous_extension = f".{extension_parts[-2]}"
    final_extension = f".{extension_parts[-1]}"
    known_extensions = COMMON_ATTACHMENT_EXTENSIONS | DANGEROUS_ATTACHMENT_EXTENSIONS

    return previous_extension in known_extensions and final_extension in known_extensions


def get_filename_extension_parts(filename: str) -> list[str]:
    clean_filename = filename.strip().lower()
    parts = [part.strip() for part in clean_filename.split(".") if part.strip()]
    return parts[1:]


def has_hidden_extension_spacing(filename: str) -> bool:
    return bool(HIDDEN_EXTENSION_SPACES_PATTERN.search(filename))


def verdict_for_score(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 35:
        return "suspicious"
    return "low_risk"


def format_reasoning(reasons: list[str]) -> str:
    return "\n".join(f"- {reason}" for reason in reasons)
