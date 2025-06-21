const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const User = require("./models/User");

// Connect to MongoDB
mongoose.connect(
  process.env.MONGODB_URI || "mongodb://localhost:27017/otp-auth-demo",
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
);

const createSuperAdmin = async () => {
  try {
    console.log("🔍 Checking for super admin...");

    // Check if super admin exists
    const existingSuperAdmin = await User.findOne({
      email: "admin844121@gmail.com",
    });

    if (existingSuperAdmin) {
      console.log("✅ Super admin already exists");
      console.log("Email:", existingSuperAdmin.email);
      console.log("Name:", existingSuperAdmin.name);
      console.log("Is Super Admin:", existingSuperAdmin.isSuperAdmin);
      console.log("Is Verified:", existingSuperAdmin.isVerified);
      console.log("Status:", existingSuperAdmin.status);

      // Test password
      const isPasswordValid = await bcrypt.compare(
        ".Chaman1",
        existingSuperAdmin.password
      );
      console.log("Password valid:", isPasswordValid);

      if (!isPasswordValid) {
        console.log("⚠️ Password mismatch, updating password...");
        const hashedPassword = await bcrypt.hash(".Chaman1", 10);
        existingSuperAdmin.password = hashedPassword;
        await existingSuperAdmin.save();
        console.log("✅ Password updated");
      }
    } else {
      console.log("❌ Super admin not found, creating...");
      const hashedPassword = await bcrypt.hash(".Chaman1", 10);
      const superAdmin = new User({
        name: "Super Admin",
        email: "admin844121@gmail.com",
        password: hashedPassword,
        isVerified: true,
        isAdmin: true,
        isSuperAdmin: true,
        status: "active",
      });
      await superAdmin.save();
      console.log("✅ Super admin created successfully");
    }

    console.log("🎯 Super admin credentials:");
    console.log("Email: admin844121@gmail.com");
    console.log("Password: .Chaman1");
  } catch (error) {
    console.error("❌ Error:", error);
  } finally {
    mongoose.connection.close();
  }
};

createSuperAdmin();
