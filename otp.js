const nodemailer = require('nodemailer');

// Generate random 6-digit OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Send OTP email
const sendOtp = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'k844121@gmail.com', // ✅ Your Gmail address
      pass: 'uwmtulagbxrijwxt'     // ✅ App password (remove spaces)
    }
  });

  try {
    const info = await transporter.sendMail({
      from: '"OTP Service" <yourgmail@gmail.com>',
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`
    });

    console.log('✅ OTP sent successfully:', info.response);
  } catch (error) {
    console.error('❌ Failed to send OTP:', error);
  }
};

// Example use
const otp = generateOTP();
sendOtp('prince844121@gmail.com', otp);
console.log('Generated OTP:', otp);
