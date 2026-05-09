var ANALYSIS_SERVER_URL = "https://creature-neatness-flattery.ngrok-free.dev/analyze";

function buildAddOn(e) {
  var email = getCurrentEmail_(e);
  var analysis = sendEmailToServer_(email);

  var card = CardService.newCardBuilder();
  card.setHeader(CardService.newCardHeader().setTitle("Email Analyzer"));

  var section = CardService.newCardSection();
  section.setHeader("Opened Email");
  section.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("Subject")
      .setText(escapeCardText_(email.subject || "(No subject)"))
  );

  addAnalysisWidgets_(section, analysis);

  card.addSection(section);
  return card.build();
}

function getCurrentEmail_(e) {
  if (!e || !e.gmail || !e.gmail.messageId || !e.gmail.accessToken) {
    throw new Error("Missing Gmail add-on message context.");
  }

  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

  var message = GmailApp.getMessageById(e.gmail.messageId);
  return {
    subject: message.getSubject(),
    sender: message.getFrom(),
    body: message.getPlainBody(),
    attachments: getAttachmentDetails_(message)
  };
}

function getAttachmentDetails_(message) {
  var attachments = message.getAttachments({
    includeInlineImages: false,
    includeAttachments: true
  });

  return attachments.map(function(attachment) {
    return {
      name: attachment.getName(),
      contentType: attachment.getContentType(),
      size: attachment.getSize()
    };
  });
}

function sendEmailToServer_(email) {
  var response;
  try {
    response = UrlFetchApp.fetch(ANALYSIS_SERVER_URL, {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(buildServerPayload_(email)),
      headers: {
        "ngrok-skip-browser-warning": "true"
      },
      muteHttpExceptions: true
    });
  } catch (error) {
    return {
      status: "error",
      error: "Could not reach analysis server: " + error.message
    };
  }

  var statusCode = response.getResponseCode();
  var responseText = response.getContentText();

  if (statusCode < 200 || statusCode >= 300) {
    return {
      status: "error",
      error: "Server returned HTTP " + statusCode + ": " + responseText
    };
  }

  try {
    return JSON.parse(responseText);
  } catch (error) {
    return {
      status: "error",
      error: "Server returned invalid JSON: " + responseText
    };
  }
}

function buildServerPayload_(email) {
  return {
    subject: email.subject,
    sender: email.sender,
    body: email.body,
    attachments: email.attachments
  };
}

function addAnalysisWidgets_(section, analysis) {
  if (!analysis || analysis.status === "error") {
    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Server response")
        .setText(escapeCardText_(analysis && analysis.error ? analysis.error : "No response"))
    );
    return;
  }

  section.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("Verdict")
      .setText(escapeCardText_(analysis.verdict || "Unknown"))
  );
  section.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("Score")
      .setText(escapeCardText_(analysis.score === undefined ? "Unknown" : analysis.score))
  );
  section.addWidget(
    CardService.newTextParagraph()
      .setText(escapeCardText_(analysis.reasoning || "No reasoning returned."))
  );
}

function escapeCardText_(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
