# OAuth Setup Guide for AI Interview Coach

This guide will help you set up Google and GitHub OAuth authentication for the AI Interview Coach application.

## 🔧 Prerequisites

1. A Google account for Google OAuth setup
2. A GitHub account for GitHub OAuth setup
3. Your application running locally or deployed

## 📋 Setup Instructions

### 1. Google OAuth Setup

#### Step 1: Create a Google Cloud Project
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API and Google OAuth2 API

#### Step 2: Configure OAuth Consent Screen
1. Go to "APIs & Services" > "OAuth consent screen"
2. Choose "External" user type
3. Fill in the required information:
   - App name: `AI Interview Coach`
   - User support email: Your email
   - Developer contact information: Your email
4. Add scopes: `email`, `profile`, `openid`
5. Save and continue

#### Step 3: Create OAuth Credentials
1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. Choose "Web application"
4. Set the name: `AI Interview Coach`
5. Add authorized redirect URIs:
   - For local development: `http://localhost:5000/auth/google/callback`
   - For production: `https://yourdomain.com/auth/google/callback`
6. Save and copy the Client ID and Client Secret

### 2. GitHub OAuth Setup

#### Step 1: Create a GitHub OAuth App
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the application details:
   - Application name: `AI Interview Coach`
   - Homepage URL: `http://localhost:5000` (or your domain)
   - Authorization callback URL: 
     - For local: `http://localhost:5000/auth/github/callback`
     - For production: `https://yourdomain.com/auth/github/callback`
4. Click "Register application"
5. Copy the Client ID and generate a Client Secret

### 3. Configure Environment Variables

Update your `.env` file with the OAuth credentials:

```env
# Google OAuth
GOOGLE_CLIENT_ID=your-actual-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-actual-google-client-secret

# GitHub OAuth
GITHUB_CLIENT_ID=your-actual-github-client-id
GITHUB_CLIENT_SECRET=your-actual-github-client-secret

# Flask Secret Key (generate a secure random key)
SECRET_KEY=your-super-secret-random-key-here
```

### 4. Generate a Secure Secret Key

You can generate a secure secret key using Python:

```python
import secrets
print(secrets.token_hex(32))
```

## 🚀 Testing OAuth Integration

### Local Testing
1. Start your Flask application: `python app.py`
2. Go to `http://localhost:5000/login`
3. Click "Google" or "GitHub" buttons
4. Complete the OAuth flow
5. You should be redirected to the dashboard

### Production Deployment
1. Update the redirect URIs in both Google and GitHub OAuth apps
2. Update your `.env` file with production URLs
3. Deploy your application
4. Test the OAuth flow on your live site

## 🔒 Security Best Practices

1. **Never commit OAuth secrets to version control**
2. **Use environment variables for all sensitive data**
3. **Implement proper state parameter validation** (already included)
4. **Use HTTPS in production** for OAuth callbacks
5. **Regularly rotate OAuth secrets**

## 🐛 Troubleshooting

### Common Issues

#### "OAuth is not configured" Error
- Check that your environment variables are properly set
- Restart your Flask application after updating `.env`

#### "Invalid redirect URI" Error
- Ensure the redirect URI in your OAuth app matches exactly
- Check for trailing slashes and HTTP vs HTTPS

#### "Invalid state parameter" Error
- This is a security feature - try logging in again
- Clear your browser cookies if the issue persists

#### Google OAuth Issues
- Ensure Google+ API is enabled in Google Cloud Console
- Check that your OAuth consent screen is properly configured
- Verify the scopes are correctly set

#### GitHub OAuth Issues
- Ensure the callback URL is exactly correct
- Check that the OAuth app is not suspended
- Verify the client ID and secret are correct

## 📝 OAuth Flow Explanation

### Google OAuth Flow
1. User clicks "Google" button
2. Redirected to Google's authorization server
3. User grants permissions
4. Google redirects back with authorization code
5. Server exchanges code for access token
6. Server fetches user profile information
7. User is logged in and redirected to dashboard

### GitHub OAuth Flow
1. User clicks "GitHub" button
2. Redirected to GitHub's authorization server
3. User grants permissions
4. GitHub redirects back with authorization code
5. Server exchanges code for access token
6. Server fetches user profile and email information
7. User is logged in and redirected to dashboard

## 🎯 Features Included

- ✅ **Secure OAuth implementation** with state parameter validation
- ✅ **Error handling** for various OAuth failure scenarios
- ✅ **User profile integration** (name, email, avatar)
- ✅ **Session management** with OAuth provider tracking
- ✅ **Fallback authentication** (regular email/password still works)
- ✅ **Responsive UI** with loading states and error messages

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Verify your OAuth app configurations
3. Check the Flask application logs for detailed error messages
4. Ensure all environment variables are properly set

---

**Note**: Replace all placeholder values (your-actual-client-id, etc.) with your real OAuth credentials before testing.