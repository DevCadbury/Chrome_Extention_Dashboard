const nodemailer = require("nodemailer");
require("dotenv").config();

async function sendMail(to, subject, html) {
  if (!to || !subject || !html) {
    throw new Error("Missing required parameters: to, subject, or html");
  }

  console.log("📧 sendMail called with:", { to, subject });

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER, // Use .env instead of hardcoding
      pass: process.env.GMAIL_APP_PASS, // Your Gmail app password
    },
  });

  try {
    // Extract OTP from HTML
    const otpMatch = html.match(/\d{6}/);
    const otp = otpMatch ? otpMatch[0] : "NO_OTP_FOUND";

    const info = await transporter.sendMail({
      from: `"OTP Service" <${process.env.GMAIL_USER}>`,
      to: to,
      subject: subject,
      text: `Your OTP is ${otp}. It expires in 10 minutes.`,
      html, // include original HTML for richer formatting if needed
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
