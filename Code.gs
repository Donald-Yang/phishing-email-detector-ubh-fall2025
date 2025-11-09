/**
 * Gmail Add-on: No Phishing Allowed
 * Displays phishing risk assessment for a selected email.
 */

// Gmail Add-on container for the sidebar card
function getContextualAddOn(e) {
  try {
    // Safely extract email messageId, errors if not found
    const messageId =
      e.gmail && e.gmail.messageId ? e.gmail.messageId : e.messageId;

    if (!messageId) {
      return buildErrorCard("No message ID found in event context.");
    }

    // Retrieves the email using its messageID and extract info from it
    const message = GmailApp.getMessageById(messageId);
    const subject = message.getSubject();
    const body = message.getPlainBody();

    // Calls the risk evaluation function to evaluate the risk level of the email using its subject and body. It also gives a reason for the risk level it provided.
    const { riskLevel, matchedReasons } = assessRisk(subject, body);

    const colorMap = {
      low: "#34a853",    // green
      medium: "#fbbc05", // yellow
      high: "#ea4335"    // red
    };

    // The actual Add-on Card configuration
    const card = CardService.newCardBuilder()
      // Header for short description of what add-on is doing
      .setHeader(
        CardService.newCardHeader()
          .setTitle("Analyzing email for phishing patterns")
          .setSubtitle("❗ Please use the information provided to decide if this email is fishy. ❗")
      )
      // Display risk level
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText(
            `<b>Risk Level:</b> <font color='${colorMap[riskLevel]}'>${riskLevel.toUpperCase()}</font>`
          )
        )
      )
      // Display reason for risk level
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText(
            matchedReasons.length
              ? `<b>Suspicious Indicators:</b><br>• ${matchedReasons.join("<br>• ")}`
              : "No obvious phishing indicators detected."
          )
        )
      )
      // Reminders for user
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText(
            "⚠️ Exercise caution if this email seems suspicious, avoid clicking any links or sharing personal information. ⚠️"
          )
        )
      )

      .build();

    return [card];
  } catch (err) {
    // Display error message if something fails
    return buildErrorCard(err.message);
  }
}


// Error card for display
function buildErrorCard(msg) {
  return [
    CardService.newCardBuilder()
      .setHeader(
        CardService.newCardHeader()
          .setTitle("Phishing Email Detector Error")
          .setSubtitle("Unable to process this email")
      )
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText("Error: " + msg)
        )
      )
      .build()
  ];
}

// Main logic behind the risk evaluation
function assessRisk(subject, body) {
  // Turn all text in the email lowercase
  const text = (subject + " " + body).toLowerCase();
  let score = 0;
  let reasons = [];

  // List of case insensative regular expressions and their descriptions
  const patterns = [
    // Existing patterns
    { re: /verify your account/i, reason: "Mentions verifying account" },
    { re: /urgent action required/i, reason: "Urgent action requested" },
    { re: /click here to login/i, reason: "Contains 'click to login' link" },
    { re: /password.*reset/i, reason: "Mentions password reset" },
    { re: /bank account/i, reason: "Mentions bank account" },
    { re: /suspended.*account/i, reason: "Mentions suspended account" },
    { re: /update.*billing/i, reason: "Requests billing update" },
    { re: /(invoice attached|bitcoin|gift card)/i, reason: "Mentions invoice, bitcoin, or gift card" },

    // Urgency and threats
    { re: /(expire|expir(ing|ed)).*(?:soon|today|immediately|within.*hours?)/i, reason: "Mentions expiration urgency" },
    { re: /limited time (offer|only)/i, reason: "Limited time offer" },
    { re: /(act now|respond (immediately|within))/i, reason: "Encourages immediate action" },
    { re: /(legal action|lawsuit|court|subpoena)/i, reason: "Mentions legal action" },
    { re: /security (alert|warning|breach)/i, reason: "Mentions security alert" },
    { re: /(unusual|suspicious) activity/i, reason: "Mentions unusual activity" },

    // Account threats
    { re: /(locked|frozen|disabled|closed).*account/i, reason: "Mentions locked/frozen account" },
    { re: /confirm (your )?identity/i, reason: "Requests identity confirmation" },
    { re: /verify.*(information|details|credentials)/i, reason: "Requests verification of info" },
    { re: /reactivate.*account/i, reason: "Mentions reactivating account" },

    // Prize/lottery scams
    { re: /(congratulations|you('ve| have) won|winner|selected)/i, reason: "Mentions winning or selection" },
    { re: /(claim.*(prize|reward)|unclaimed (funds|money))/i, reason: "Mentions prize or reward" },
    { re: /(lottery|sweepstakes)/i, reason: "Mentions lottery/sweepstakes" },

    // Financial requests
    { re: /(payment (failed|declined|required)|outstanding (payment|balance))/i, reason: "Mentions payment issues" },
    { re: /(refund (pending|available)|claim.*refund)/i, reason: "Mentions refund" },
    { re: /tax refund/i, reason: "Mentions tax refund" },
    { re: /wire transfer/i, reason: "Mentions wire transfer" },
    { re: /(update|verify|confirm).*(credit card|payment method)/i, reason: "Mentions credit card/payment update" },

    // Credential harvesting
    { re: /(reset|change|update).*(password|credentials)/i, reason: "Mentions password or credential update" },
    { re: /social security number/i, reason: "Requests SSN" },
    { re: /full access/i, reason: "Mentions full access" },

    // Generic suspicious phrases
    { re: /dear (customer|user|member|valued)/i, reason: "Generic greeting" },
    { re: /click here/i, reason: "Contains 'click here'" },
    { re: /(open|download|view).*(attachment|file|document)/i, reason: "Mentions attachments" },
    { re: /kindly (reply|respond|confirm|provide)/i, reason: "Requests action politely" },

    // Package delivery scams
    { re: /(delivery|package|shipment).*(failed|pending|waiting)/i, reason: "Mentions delivery issues" },
    { re: /customs (fee|charge|payment)/i, reason: "Mentions customs fees" },

    // Business email compromise
    { re: /(ceo|president|director).*(urgent|immediate)/i, reason: "Mentions CEO/director urgent request" },
    { re: /urgent.*wire/i, reason: "Mentions urgent wire transfer" },
    { re: /change.*(bank|payment|account).*details/i, reason: "Mentions changing payment details" },

    // Typosquatting common domains
    { re: /(paypa1|g00gle|micros0ft|arnaz0n|app1e)/i, reason: "Mentions suspicious/typosquatted domains" },

    // Suspicious links patterns
    { re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, reason: "Contains IP address link" },
    { re: /\.(tk|ml|ga|cf|gq)\b/i, reason: "Uses suspicious top-level domain" },
    { re: /(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly)/i, reason: "Contains shortened URL" }
  ];


  // Loop through the list above, increasing the score for every pattern it detects, and collects the reasons
  patterns.forEach(p => {
    if (p.re.test(text)) {
      score++;
      reasons.push(p.reason);
    }
  });

  // Convert the score from a number to words that the user can more easily understand
  let risk = "low";     // 0-1 risk = low
  if (score >= 5) risk = "high"; // 5+ risk = high
  else if (score >= 2) risk = "medium"; // 2-4 risk = medium

  return { riskLevel: risk, matchedReasons: reasons };
}
