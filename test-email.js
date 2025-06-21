const nodemailer = require('nodemailer');

// Test Gmail SMTP configuration
const testEmail = async () => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'k844121@gmail.com',
      pass: 'uwmtulagbxrijwxt'
    }
  });

  try {
    console.log('📧 Testing email configuration...');
    
    const info = await transporter.sendMail({
      from: '"OTP Service" <k844121@gmail.com>',
      to: 'prince844121@gmail.com', // Change this to your email
      subject: 'Test Email - OTP System',
      text: 'This is a test email from your OTP system. If you receive this, your email configuration is working!'
    });

    console.log('✅ Test email sent successfully:', info.response);
    console.log('📧 Message ID:', info.messageId);
  } catch (error) {
    console.error('❌ Test email failed:', error.message);
    console.error('❌ Full error:', error);
  }
};

testEmail(); 