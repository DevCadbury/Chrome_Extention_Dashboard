const nodemailer = require("nodemailer");
require("dotenv").config();

async function sendMail(to, subject, html) {
  if (!to || !subject || !html) {
    throw new Error("Missing required parameters: to, subject, or html");
  }

  console.log("📧 sendMail called with:", { to, subject });

  // Use environment variables or fallback to hardcoded values
  const gmailUser = process.env.GMAIL_USER || "k844121@gmail.com";
  const gmailPass = process.env.GMAIL_APP_PASS || "uwmtulagbxrijwxt";

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: gmailUser,
      pass: gmailPass,
    },
  });

  try {
    // Extract OTP from HTML for OTP emails
    const otpMatch = html.match(/\d{6}/);
    const otp = otpMatch ? otpMatch[0] : null;

    // Create text version of email
    let textContent = subject;
    if (otp) {
      textContent = `Your OTP is ${otp}. It expires in 10 minutes.`;
    } else {
      // For non-OTP emails, create a simple text version
      textContent = `Please check the HTML version of this email for complete information.\n\nSubject: ${subject}`;
    }

    const info = await transporter.sendMail({
      from: `"OTP Service" <${gmailUser}>`,
      to: to,
      subject: subject,
      text: textContent,
      html: html, // include original HTML for richer formatting
    });

    console.log("✅ Email sent successfully:", info.response);
    console.log("📧 Message ID:", info.messageId);
    return info;
  } catch (error) {
    console.error("❌ Failed to send email:", error.message);
    throw new Error("Failed to send email: " + error.message);
  }
}

module.exports = sendMail;
