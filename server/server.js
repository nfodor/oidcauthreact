const express = require('express');
const passport = require('passport');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const openApiSpec = require('./openapi.json');
require('dotenv').config();
const crypto = require('crypto');

mongoose.set('strictQuery', true); // Fix deprecation warning

const app = express();

// Rate limiting setup
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

const refreshLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50, // Limit each IP to 50 refresh requests per hour
  message: 'Too many token refresh requests, please try again later.'
});

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));

// Apply rate limiting to auth routes
app.use('/auth', authLimiter);
app.use('/auth/refresh-token', refreshLimiter);

app.use(session({ 
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false, 
  saveUninitialized: true 
}));
app.use(passport.initialize());
app.use(passport.session());

// MongoDB User Model
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  provider: String,
  role: { type: String, enum: ['user', 'admin', 'editor', 'viewer'], default: 'user' },
  emailVerified: { type: Boolean, default: false },
  emailVerificationToken: String,
});
const User = mongoose.model('User', UserSchema);

// MongoDB Refresh Token Model
const RefreshTokenSchema = new mongoose.Schema({
  token: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt: { type: Date, required: true }
});

const RefreshToken = mongoose.model('RefreshToken', RefreshTokenSchema);

// MongoDB Content Model
const ContentSchema = new mongoose.Schema({
  title: { type: String, required: true },
  body: { type: String, required: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});
const Content = mongoose.model('Content', ContentSchema);

// Helper function to generate tokens
const generateTokens = async (user) => {
  const tokenExpiry = parseInt(process.env.TOKEN_EXPIRY) || 900; // 15 minutes default
  const refreshExpiry = parseInt(process.env.REFRESH_TOKEN_EXPIRY) || 604800; // 7 days default
  
  console.log('Generating tokens with expiry:', {
    tokenExpiry,
    refreshExpiry,
    now: new Date().toISOString()
  });

  const accessToken = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: tokenExpiry }
  );

  const refreshToken = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: refreshExpiry }
  );

  // Save refresh token to database
  await RefreshToken.create({
    token: refreshToken,
    user: user._id,
    expiresAt: new Date(Date.now() + refreshExpiry * 1000)
  });

  // Set cookies
  return { 
    accessToken, 
    refreshToken,
    expiresIn: tokenExpiry,
    cookieOptions: {
      accessTokenCookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        maxAge: tokenExpiry * 1000
      },
      refreshTokenCookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        maxAge: refreshExpiry * 1000,
        path: '/auth/refresh-token' // Only sent to refresh endpoint
      }
    }
  };
};

// JWT Middleware to authenticate protected routes
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.accessToken || req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    console.log('Verifying token at:', new Date().toISOString());
    const decoded = jwt.decode(token);
    console.log('Token payload:', decoded);
    console.log('Token expiration:', new Date(decoded.exp * 1000).toISOString());
    
    const verified = jwt.verify(token, process.env.JWT_SECRET, {
      ignoreExpiration: false
    });
    req.user = verified;
    next();
  } catch (err) {
    console.log('Token verification error:', err.name, err.message);
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Token expired',
        code: 'TOKEN_EXPIRED',
        expiredAt: err.expiredAt
      });
    }
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Role-based Authorization Middleware
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
    }
    next();
  };
};

// Authentication Routes
app.post('/auth/register', async (req, res) => {
  try {
    console.log('Received registration request:', req.body);
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ 
        message: 'Please provide all required fields',
        missing: {
          email: !email,
          password: !password,
          name: !name
        }
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ 
        message: 'User already exists. Please login instead.',
        code: 'USER_EXISTS'
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      email,
      password: hashedPassword,
      name,
      role: 'user'
    });

    await user.save();

    const tokens = await generateTokens(user);
    const userResponse = user.toObject();
    delete userResponse.password;

    // Set cookies
    res.cookie('accessToken', tokens.accessToken, tokens.cookieOptions.accessTokenCookie);
    res.cookie('refreshToken', tokens.refreshToken, tokens.cookieOptions.refreshTokenCookie);

    console.log('User registered successfully:', userResponse);
    res.status(201).json({
      user: userResponse,
      expiresIn: tokens.expiresIn
    });
  } catch (error) {
    console.error('Error in /auth/register:', error);
    // Check for MongoDB duplicate key error
    if (error.code === 11000) {
      return res.status(409).json({ 
        message: 'User already exists. Please login instead.',
        code: 'USER_EXISTS'
      });
    }
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    console.log('Login attempt:', {
      email: req.body.email,
      hasPassword: !!req.body.password,
      timestamp: new Date().toISOString()
    });
    
    const { email, password } = req.body;

    if (!email || !password) {
      console.log('Missing credentials:', { email: !email, password: !password });
      return res.status(400).json({ 
        message: 'Please provide email and password',
        missing: {
          email: !email,
          password: !password
        }
      });
    }

    const user = await User.findOne({ email });
    console.log('User lookup result:', {
      email,
      found: !!user,
      userId: user?._id,
      userRole: user?.role
    });
    
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    console.log('Password validation:', {
      userId: user._id,
      validPassword,
      passwordLength: password.length,
      hashedLength: user.password.length
    });
    
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const tokens = await generateTokens(user);
    const userResponse = user.toObject();
    delete userResponse.password;

    // Set cookies
    res.cookie('accessToken', tokens.accessToken, tokens.cookieOptions.accessTokenCookie);
    res.cookie('refreshToken', tokens.refreshToken, tokens.cookieOptions.refreshTokenCookie);

    console.log('Login successful:', {
      userId: user._id,
      email: user.email,
      role: user.role,
      tokenExpiry: tokens.expiresIn,
      cookieOptions: {
        access: tokens.cookieOptions.accessTokenCookie,
        refresh: tokens.cookieOptions.refreshTokenCookie
      }
    });
    
    res.json({
      user: userResponse,
      expiresIn: tokens.expiresIn
    });
  } catch (error) {
    console.error('Login error:', {
      error: error.message,
      stack: error.stack,
      email: req.body.email
    });
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

app.post('/auth/refresh-token', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }

    // Verify the refresh token exists and is not expired
    const savedToken = await RefreshToken.findOne({ token: refreshToken })
      .populate('user');

    if (!savedToken) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    if (savedToken.expiresAt < new Date()) {
      await RefreshToken.deleteOne({ _id: savedToken._id });
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      return res.status(401).json({ message: 'Refresh token expired' });
    }

    // Verify the JWT
    try {
      jwt.verify(refreshToken, process.env.JWT_SECRET);
    } catch (err) {
      await RefreshToken.deleteOne({ _id: savedToken._id });
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    // Generate new tokens
    const tokens = await generateTokens(savedToken.user);

    // Delete the old refresh token
    await RefreshToken.deleteOne({ _id: savedToken._id });

    // Set new cookies
    res.cookie('accessToken', tokens.accessToken, tokens.cookieOptions.accessTokenCookie);
    res.cookie('refreshToken', tokens.refreshToken, tokens.cookieOptions.refreshTokenCookie);

    res.json({
      expiresIn: tokens.expiresIn
    });
  } catch (error) {
    console.error('Error in /auth/refresh-token:', error);
    res.status(500).json({ message: 'Error refreshing token', error: error.message });
  }
});

app.post('/auth/logout', authenticateJWT, async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      await RefreshToken.deleteOne({ token: refreshToken });
    }
    
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Error in /auth/logout:', error);
    res.status(500).json({ message: 'Error logging out', error: error.message });
  }
});

/**
 * @swagger
 * /content:
 *   post:
 *     summary: Create new content
 *     description: Allows an admin or editor to create content.
 *     operationId: createContent
 *     tags:
 *       - content
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               body:
 *                 type: string
 *     responses:
 *       201:
 *         description: Content created successfully.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Content'
 *       400:
 *         description: Bad request.
 *       403:
 *         description: Forbidden.
 *       401:
 *         description: Unauthorized.
 *       500:
 *         description: Internal server error.
 */
app.post('/content', authenticateJWT, authorizeRole(['admin', 'editor']), async (req, res) => {
  try {
    const { title, body } = req.body;

    if (!title || !body) {
      return res.status(400).json({ message: 'Please provide title and body' });
    }

    const content = new Content({
      title,
      body,
      createdBy: req.user.id,
    });
    await content.save();
    res.status(201).json(content);
  } catch (error) {
    console.error('Error in POST /content:', error);
    res.status(500).json({ message: 'Error creating content', error: error.message });
  }
});

/**
 * @swagger
 * /content/{id}:
 *   put:
 *     summary: Update content
 *     description: Allows an admin or editor to update existing content.
 *     operationId: updateContent
 *     tags:
 *       - content
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: Content ID
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               body:
 *                 type: string
 *     responses:
 *       200:
 *         description: Content updated successfully.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Content'
 *       400:
 *         description: Bad request.
 *       404:
 *         description: Content not found.
 *       403:
 *         description: Forbidden.
 *       401:
 *         description: Unauthorized.
 */
app.put('/content/:id', authenticateJWT, authorizeRole(['admin', 'editor']), async (req, res) => {
  try {
    const { title, body } = req.body;
    const content = await Content.findByIdAndUpdate(
      req.params.id,
      { title, body },
      { new: true }
    );
    if (!content) return res.status(404).json({ message: 'Content not found' });
    res.json(content);
  } catch (error) {
    console.error('Error in PUT /content/:id:', error);
    res.status(500).json({ message: 'Error updating content', error: error.message });
  }
});

/**
 * @swagger
 * /content/{id}:
 *   get:
 *     summary: Get content by ID
 *     description: Allows an authenticated user to retrieve content by ID.
 *     operationId: getContentById
 *     tags:
 *       - content
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: Content ID
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Content retrieved successfully.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Content'
 *       404:
 *         description: Content not found.
 *       401:
 *         description: Unauthorized.
 */
app.get('/content/:id', authenticateJWT, async (req, res) => {
  try {
    const content = await Content.findById(req.params.id);
    if (!content) return res.status(404).json({ message: 'Content not found' });
    res.json(content);
  } catch (error) {
    console.error('Error in GET /content/:id:', error);
    res.status(500).json({ message: 'Error retrieving content', error: error.message });
  }
});

/**
 * @swagger
 * /content:
 *   get:
 *     summary: Get all content
 *     description: Allows an authenticated user to retrieve all content.
 *     operationId: getAllContent
 *     tags:
 *       - content
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Content retrieved successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Content'
 *       401:
 *         description: Unauthorized.
 */
app.get('/content', authenticateJWT, async (req, res) => {
  try {
    const contents = await Content.find();
    res.json(contents);
  } catch (error) {
    console.error('Error in GET /content:', error);
    res.status(500).json({ message: 'Error retrieving content', error: error.message });
  }
});

/**
 * @swagger
 * /content/{id}:
 *   delete:
 *     summary: Delete content by ID
 *     description: Allows an admin to delete content by ID.
 *     operationId: deleteContentById
 *     tags:
 *       - content
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: Content ID
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: Content deleted successfully.
 *       404:
 *         description: Content not found.
 *       403:
 *         description: Forbidden.
 *       401:
 *         description: Unauthorized.
 */
app.delete('/content/:id', authenticateJWT, authorizeRole(['admin']), async (req, res) => {
  try {
    const content = await Content.findByIdAndDelete(req.params.id);
    if (!content) return res.status(404).json({ message: 'Content not found' });
    res.status(204).send();
  } catch (error) {
    console.error('Error in DELETE /content/:id:', error);
    res.status(500).json({ message: 'Error deleting content', error: error.message });
  }
});

// Admin Routes
app.put('/admin/users/:id/role', authenticateJWT, authorizeRole(['admin']), async (req, res) => {
  try {
    const { role } = req.body;
    if (!['user', 'admin', 'editor', 'viewer'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).json({ message: 'Error updating user role', error: error.message });
  }
});

// Temporary endpoint to set first admin (remove in production)
app.post('/temp/set-admin', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOneAndUpdate(
      { email },
      { role: 'admin' },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error('Error setting admin:', error);
    res.status(500).json({ message: 'Error setting admin', error: error.message });
  }
});

// Test endpoint
app.get('/test', (req, res) => {
  res.json({ message: 'Server is running correctly' });
});

// Authentication Routes
// Serve OpenAPI documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openApiSpec));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error', error: err.message });
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  directConnection: true
})
.then(() => {
  console.log('Connected to MongoDB successfully');
  console.log('Database URI:', process.env.MONGO_URI);
  
  // Create an admin user if none exists
  return User.findOne({ role: 'admin' }).then(admin => {
    if (!admin) {
      console.log('Creating default admin user...');
      const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
      const salt = bcrypt.genSaltSync(10);
      const hashedPassword = bcrypt.hashSync(adminPassword, salt);
      
      return User.create({
        email: 'admin@example.com',
        password: hashedPassword,
        name: 'Admin User',
        role: 'admin'
      }).then(() => {
        console.log('Default admin user created successfully');
      });
    }
  });
})
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log('Environment:', process.env.NODE_ENV || 'development');
  console.log('Client URL:', process.env.CLIENT_URL || 'http://localhost:3000');
});