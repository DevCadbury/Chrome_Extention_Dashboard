# Chrome Extension Dashboard

A secure user registration and admin management system built with Node.js, Express, and MongoDB. Features include OTP email verification, admin dashboard, and Gemini API key management.

## Features

- 🔐 **Secure Authentication**: User registration with OTP email verification
- 👥 **Admin Management**: Comprehensive admin dashboard with user management
- 🔑 **API Key Management**: Gemini API key validation and storage
- 📧 **Email Integration**: Nodemailer with Gmail SMTP
- 🛡️ **JWT Security**: JSON Web Token authentication
- 📊 **Activity Logging**: Detailed user activity tracking
- 🎨 **Modern UI**: Clean and responsive interface

## Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: MongoDB with Mongoose
- **Authentication**: JWT, bcrypt
- **Email**: Nodemailer
- **Frontend**: HTML, CSS, JavaScript
- **Deployment**: Vercel

## Local Development

### Prerequisites

- Node.js (v14 or higher)
- MongoDB Atlas account
- Gmail account for SMTP

### Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/DevCadbury/Chrome_Extention_Dashboard.git
   cd Chrome_Extention_Dashboard
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Environment Variables**
   Create a `.env` file in the root directory:

   ```env
   MONGO_URI=your_mongodb_atlas_connection_string
   JWT_SECRET=your_jwt_secret_key
   EMAIL_USER=your_gmail_address
   EMAIL_PASS=your_gmail_app_password
   PORT=5000
   ```

4. **Run the application**

   ```bash
   npm start
   ```

5. **Access the application**
   - Login: http://localhost:5000/login
   - Admin Dashboard: http://localhost:5000/admin
   - Registration: http://localhost:5000/register
   - Settings: http://localhost:5000/settings

## Vercel Deployment

### Prerequisites

- Vercel account
- MongoDB Atlas database
- Gmail SMTP credentials

### Deployment Steps

1. **Install Vercel CLI**

   ```bash
   npm install -g vercel
   ```

2. **Login to Vercel**

   ```bash
   vercel login
   ```

3. **Deploy to Vercel**

   ```bash
   vercel --prod
   ```

4. **Set Environment Variables**
   In your Vercel dashboard, go to your project settings and add these environment variables:

   - `MONGO_URI`: Your MongoDB Atlas connection string
   - `JWT_SECRET`: Your JWT secret key
   - `EMAIL_USER`: Your Gmail address
   - `EMAIL_PASS`: Your Gmail app password

5. **Redeploy**
   ```bash
   vercel --prod
   ```

### Environment Variables for Vercel

Make sure to set these in your Vercel project settings:

| Variable     | Description                      | Example                                                        |
| ------------ | -------------------------------- | -------------------------------------------------------------- |
| `MONGO_URI`  | MongoDB Atlas connection string  | `mongodb+srv://username:password@cluster.mongodb.net/database` |
| `JWT_SECRET` | Secret key for JWT tokens        | `your-super-secret-jwt-key`                                    |
| `EMAIL_USER` | Gmail address for sending emails | `your-email@gmail.com`                                         |
| `EMAIL_PASS` | Gmail app password               | `your-app-password`                                            |

## API Endpoints

### Authentication

- `POST /api/register` - User registration
- `POST /api/login` - User login
- `POST /api/verify-otp` - OTP verification
- `POST /api/forgot-password` - Forgot password
- `POST /api/reset-password` - Reset password

### Admin

- `GET /api/admin/users` - Get all users (Admin only)
- `POST /api/admin/create-user` - Create new user (Admin only)
- `POST /api/admin/reset-password` - Reset user password (Admin only)
- `POST /api/admin/ban-user` - Ban/unban user (Admin only)

### Settings

- `POST /api/settings/validate-gemini` - Validate Gemini API key
- `DELETE /api/settings/remove-gemini` - Remove Gemini API key

## Default Super Admin

The system automatically creates a default super admin on first run:

- **Email**: superadmin@example.com
- **Password**: superadmin123

**Important**: Change these credentials after first login!

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- Role-based access control
- Input validation and sanitization
- CORS protection
- Rate limiting (can be added)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For support, please open an issue on GitHub or contact the development team.
