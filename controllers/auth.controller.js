import jwksClient from 'jwks-rsa';
import jwt from 'jsonwebtoken';
import { generateNonce, generateState } from '../utils/authUtils.js';
import axios from 'axios';
import User from '../models/user.model.js';

const getJwksClient = () => {
  return jwksClient({
    jwksUri: process.env.GOOGLE_JWKS_URL,
    cache: true,
    rateLimit: true,
  });
};

const getSigninKey = async (kid) => {
  const client = getJwksClient();
  return new Promise((resolve, reject) => {
    client.getSigningKey(kid, (err, key) => {
      if (err) {
        reject(err);
      }
      const signinkey = key.getPublicKey();
      resolve(signinkey);
    });
  });
};

const verifyGoogleToken = async (token) => {
  try {
    const decodedToken = jwt.decode(token, { complete: true });

    if (!decodedToken) {
      throw new Error('Invalid token');
    }

    const kid = decodedToken.header.kid;

    const signinkey = await getSigninKey(kid);

    const verificationToken = jwt.verify(token, signinkey, {
      algorithms: ['RS256'],
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    return verificationToken;
  } catch (error) {
    throw new Error('token verication failed');
  }
};

const googleLogin = async (req, res) => {
  const state = generateState();
  const nonce = generateNonce();

  console.log('Generated state:', state);
  console.log('Generated nonce:', nonce);

  res.cookie('oauth_state', state, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 600000,
  });

  res.cookie('oauth_nonce', nonce, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 600000,
  });

  const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${process.env.GOOGLE_REDIRECT_URI}&response_type=code&scope=openid%20email%20profile&state=${state}&nonce=${nonce}`;

  console.log('Redirecting to:', googleAuthUrl);
  res.redirect(googleAuthUrl);
};

const googleCallback = async (req, res) => {
  try {
    const { code, state } = req.query;

    console.log('Received Cookies:', req.cookies);
    const savedState = req.cookies.oauth_state;
    const savedNonce = req.cookies.oauth_nonce;

    res.clearCookie('oauth_state');
    res.clearCookie('oauth_nonce');

    console.log('Returned state from Google:', state);
    console.log('Saved cookie state:', savedState);
    console.log('Cookies:', req.cookies);

    if (!state || !savedState || state !== savedState) {
      return res.status(400).json({ error: 'Invalid state parameter' });
    }

    // exchange code for token
    const tokenResponse = await axios.post(
      'https://oauth2.googleapis.com/token',
      null,
      {
        params: {
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          redirect_uri: process.env.GOOGLE_REDIRECT_URI,
          grant_type: 'authorization_code',
          code,
        },
      },
    );

    const { id_token, refresh_token } = tokenResponse.data;

    if (!id_token) {
      return res.status(400).json({ error: 'Invalid token response' });
    }

    const decodeToken = await verifyGoogleToken(id_token);

    if (!decodeToken.nonce || decodeToken.nonce !== savedNonce) {
      return res.status(400).json({ error: 'Invalid nonce' });
    }

    // Here you can save the user information to your database or session

    let user = await User.findOne({
      googleId: decodeToken.sub,
    });

    if (!user) {
      user = await User.create({
        googleId: decodeToken.sub,
        email: decodeToken.email,
        name: decodeToken.name,
        refresh_token: refresh_token || null,
      });
    } else {
      // If user already exists, you can update the refresh token
      user.refresh_token = refresh_token;
      await user.save();
    }

    // Generate JWT token for your application
    const accessToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: '1h',
      },
    );

    // Set the JWT token in the cookie
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000, // 1 hour
    });

    // Redirect to your application
    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error('Error during Google callback:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export { googleLogin, googleCallback };
