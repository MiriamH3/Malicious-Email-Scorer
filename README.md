# Malicious Email Scorer

Malicious Email Scorer is a Gmail Add-on and Python backend that analyze the email currently opened by the user and return an explainable maliciousness score.

The project was built for the Upwind bootcamp home assignment. The main goal is not to claim production-grade phishing detection, but to demonstrate a thoughtful, secure, and explainable approach to analyzing untrusted email content.

## What the user sees

When the add-on is opened on a Gmail message, it:

1. Reads the current email only.
2. Extracts the sender, subject, plain text body, HTML links, and attachment metadata.
3. Sends those signals to the backend service.
4. Displays a card with:
   - the email subject
   - the verdict
   - the numeric score
   - a full reasoning section explaining which signals contributed to the result

Example response rendered by the add-on:

```text
Verdict: suspicious
Score: 45
Reasoning:
- Body contains suspicious keyword or phrase: 'urgent'.
- Contains 1 link(s).
- Combines urgency language with link(s), increasing phishing risk.
```

## Architecture

```text
Gmail message opened by user
        |
        v
Google Workspace Add-on
code.gs
        | POST /analyze
        v
Python HTTP backend
app.py
        |
        v
Analyzer / scoring logic
analyzer.py
        |
        v
JSON response rendered back in Gmail card
```

### Files

| File | Purpose |
| --- | --- |
| `appsscript.json` | Google Apps Script manifest for the Gmail Add-on. |
| `code.gs` | Gmail Add-on code. Extracts email data, calls the backend, and renders the card UI. |
| `app.py` | Python HTTP server. Exposes `GET /health` and `POST /analyze`. |
| `analyzer.py` | Phishing scoring and explainability logic. |
| `README.md` | Project documentation and design notes. |

## Data flow

The add-on sends this JSON shape to the backend:

```json
{
  "subject": "Payment notice",
  "sender": "Bank Support <alerts@gmail.com>",
  "body": "Plain text body extracted from Gmail",
  "links": [
    {
      "url": "https://bit.ly/example",
      "text": "Open secure document"
    }
  ],
  "attachments": [
    {
      "name": "invoice.pdf.exe",
      "contentType": "application/octet-stream",
      "size": 2048
    }
  ]
}
```

The backend returns:

```json
{
  "status": "ok",
  "score": 75,
  "verdict": "malicious",
  "reasoning": "- Contains URL shortener link(s): bit.ly.\n- Attachment has a double extension...",
  "received": {
    "subject": "Payment notice",
    "sender": "Bank Support <alerts@gmail.com>",
    "bodyLength": 36,
    "linkCount": 1,
    "links": [],
    "attachmentCount": 1,
    "attachments": []
  }
}
```

## Gmail Add-on

The add-on is configured in `appsscript.json`.

Important manifest choices:

- Add-on name: `Malicious Email Scorer`
- Runtime: `V8`
- Time zone: `Asia/Jerusalem`
- Trigger: `buildAddOn`
- Host: Gmail

### OAuth scopes

```json
[
  "https://www.googleapis.com/auth/gmail.addons.execute",
  "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
  "https://www.googleapis.com/auth/script.external_request"
]
```

Security reasoning:

- `gmail.addons.current.message.readonly` is intentionally scoped to the currently opened message instead of granting broad mailbox access.
- `script.external_request` is required because the add-on sends the extracted signals to the Python backend.
- The add-on does not modify, delete, label, or send emails.

### Extracted Gmail signals

`code.gs` extracts:

- `subject` using `message.getSubject()`
- `sender` using `message.getFrom()`
- plain text body using `message.getPlainBody()`
- HTML anchor links using `message.getBody()`
- attachment metadata using `message.getAttachments()`

For HTML links, the add-on sends both:

- the real URL from the anchor `href`
- the visible text shown to the user

This matters because phishing emails often hide a suspicious URL behind harmless-looking button text.

## Backend

The backend is intentionally lightweight and uses only the Python standard library.

### Endpoints

#### `GET /health`

Returns:

```json
{ "status": "ok" }
```

#### `POST /analyze`

Accepts the add-on JSON payload and returns the analysis result.

Request validation in `app.py`:

- body is required
- body must be valid JSON
- body must be a JSON object
- request body is limited to 1 MB

## Analyzer and scoring logic

`analyzer.py` normalizes the incoming payload and applies rule-based phishing heuristics. The score is capped at 100.

Verdict thresholds:

| Score | Verdict |
| --- | --- |
| `0-34` | `low_risk` |
| `35-69` | `suspicious` |
| `70-100` | `malicious` |

### Signals currently analyzed

#### Keyword signals

Suspicious keywords include terms such as:

- `urgent`
- `suspended`
- `password`
- `verify`
- `login`
- `security alert`

To reduce false positives:

- common financial words like `bank`, `account`, and `payment` only add 2 points when they appear only in the body
- suspicious words in the subject receive double weight because subject-line pressure is a stronger phishing signal

#### URL signals

The analyzer scans URLs found in:

- plain text body
- HTML anchor `href` values sent by the add-on

It detects:

- insecure `http://` links
- URL shorteners such as `bit.ly`, `tinyurl.com`, `t.co`, `rebrand.ly`
- direct IP address URLs such as `http://192.168.1.10/login`
- urgency plus URL correlation, for example `urgent` + a link

The URL checks are performed in one pass over the collected URL list.

#### Sender signals

The analyzer checks:

- missing or unclear sender domain
- public-domain impersonation when the email references a bank or company but comes from a public domain
- display-name spoofing, for example `PayPal Support <alerts@gmail.com>`
- typosquatting in the sender domain, such as:
  - `paypa1.com`
  - `micros0ft.com`

Typosquatting is detected using:

- number substitution checks
- `difflib` similarity against popular brands: `google`, `paypal`, `microsoft`, `bankleumi`, `apple`

#### Attachment signals

The add-on sends attachment metadata only, not file contents.

The analyzer checks:

- risky file extensions, such as `.exe`, `.js`, `.vbs`, `.zip`
- double extensions, such as `invoice.pdf.exe`
- hidden extension spacing, such as `invoice.pdf                    .exe`

Double extensions add enough score to make the email at least suspicious.

## Running locally

Requirements:

- Python 3.10+
- Google Apps Script / Gmail account for the add-on
- Optional: ngrok or another public tunnel for live Gmail testing

Start the backend:

```bash
python3 app.py
```

By default it listens on:

```text
http://0.0.0.0:8080
```

You can override the port:

```bash
PORT=9000 python3 app.py
```

Health check:

```bash
curl http://localhost:8080/health
```

Analyze a sample email:

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent payment notice",
    "sender": "PayPal Support <alerts@gmail.com>",
    "body": "Your account is suspended. Visit http://192.168.1.10/login",
    "links": [
      {
        "url": "https://bit.ly/example",
        "text": "Verify now"
      }
    ],
    "attachments": [
      {
        "name": "invoice.pdf.exe",
        "contentType": "application/octet-stream",
        "size": 2048
      }
    ]
  }'
```

## Running with Gmail and ngrok

For a live demo, Gmail must be able to reach the backend through a public HTTPS URL.

Example with ngrok:

```bash
python3 app.py
ngrok http 8080
```

Then update this constant in `code.gs`:

```javascript
var ANALYSIS_SERVER_URL = "https://your-ngrok-domain.ngrok-free.dev/analyze";
```

The current development value is:

```javascript
var ANALYSIS_SERVER_URL = "https://creature-neatness-flattery.ngrok-free.dev/analyze";
```

If the ngrok URL changes, this value must be updated before deploying the Apps Script project.

## Deploying the Google Workspace Add-on

One common workflow:

1. Create a Google Apps Script project.
2. Copy `appsscript.json` into the Apps Script manifest.
3. Copy `code.gs` into the Apps Script editor.
4. Update `ANALYSIS_SERVER_URL` to the live backend URL.
5. Deploy/test the Gmail Add-on from Apps Script.
6. Open a Gmail message and launch the add-on.

## Security considerations

The implementation treats email data as untrusted input.

Current safeguards:

- least-privilege Gmail scope for the currently opened message
- no mailbox-wide read permission
- no email modification permissions
- backend request size limit
- JSON type validation
- HTML link extraction sends only URL/text pairs, not the full raw HTML body
- attachment analysis uses metadata only, not file contents
- add-on UI escapes server-provided text before rendering

Important limitations:

- The backend currently has no authentication. For a production system, the add-on should authenticate requests to the backend.
- The ngrok URL is suitable for demos, not production.
- Attachments are scored by metadata only; file content is not downloaded or scanned.
- URL destination reputation and redirect expansion are not implemented.
- The scoring model is rule-based and explainable, but not a replacement for a production phishing detection engine.

## Design decisions and trade-offs

### Backend separation

The add-on extracts Gmail-specific data and renders the result. The backend owns the analysis logic. This keeps Apps Script small and makes the phishing logic easier to test and evolve.

### Least privilege

The add-on requests access only to the current Gmail message. This is a deliberate security choice and aligns with the task requirement to analyze the opened email.

### Metadata-only attachment analysis

The current version does not upload full attachments. This reduces privacy and security risk for a demo while still allowing useful checks such as double extensions and risky file types.

## What I would improve next
- Implement an AI-driven approach to detect urgency in emails more accurately.
- Develop a more sophisticated scoring algorithm where the risk score increases exponentially based on the combination of suspicious signals.
- Add optional attachment hashing or safe sandbox scanning.

