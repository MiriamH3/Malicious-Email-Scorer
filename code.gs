function buildAddOn(e) {
  var email = getCurrentEmail_(e);

  var card = CardService.newCardBuilder();
  card.setHeader(CardService.newCardHeader().setTitle("Email Analyzer"));

  var section = CardService.newCardSection();
  section.setHeader("Opened Email");
  section.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("Subject")
      .setText(escapeCardText_(email.subject || "(No subject)"))
  );

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

function escapeCardText_(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
