require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { PrismaClient } = require('@prisma/client');
const debug = require('debug')('app:auth');
const bcrypt = require('bcryptjs');
const Joi = require('joi');

const prisma = new PrismaClient();
const app = express();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Passport configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback",
    proxy: true
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      console.log('Google Profile:', profile);
      
      // First try to find user by googleId
      const existingUser = await prisma.user.findFirst({
        where: { 
          OR: [
            { googleId: profile.id },
            { email: profile.emails[0].value } // Also check email to link accounts
          ]
        }
      });

      if (existingUser) {
        // If user exists but doesn't have googleId (found by email), update their googleId
        if (!existingUser.googleId) {
          const updatedUser = await prisma.user.update({
            where: { id: existingUser.id },
            data: { googleId: profile.id }
          });
          return done(null, { ...updatedUser, accessToken });
        }
        return done(null, { ...existingUser, accessToken });
      }

      // Create new user if none exists
      const newUser = await prisma.user.create({
        data: {
          googleId: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName
        }
      });

      done(null, { ...newUser, accessToken });
    } catch (error) {
      console.error('Google Strategy Error:', error);
      done(error, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id }
    });
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Auth routes
app.get('/api/auth/google', (req, res, next) => {
  debug('Starting Google authentication');
  debug('Client ID:', process.env.GOOGLE_CLIENT_ID);
  debug('Callback URL:', "/api/auth/google/callback");
  
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })(req, res, next);
});

app.get('/api/auth/google/callback', (req, res, next) => {
  debug('Received callback from Google');
  debug('Query params:', req.query);
  
  passport.authenticate('google', {
    failureRedirect: '/login',
    successRedirect: process.env.FRONTEND_URL,
    failureMessage: true
  })(req, res, next);
});

app.get('/api/auth/user', (req, res) => {
  if (!req.user) {
    return res.json(null);
  }
  
  if (req.user.googleId) {
    return res.json({
      ...req.user,
      accessToken: req.user.accessToken
    });
  }
  
  res.json(req.user);
});

app.post('/api/auth/logout', (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      res.clearCookie('connect.sid');
      return res.json({ success: true });
    }

    req.logout(function(err) {
      if (err) {
        console.error('Logout error:', err);
        return res.status(500).json({ error: 'Error during logout' });
      }
      
      // Only destroy session after successful logout
      req.session.destroy((err) => {
        if (err) {
          console.error('Session destruction error:', err);
          return res.status(500).json({ error: 'Error during session destruction' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true });
      });
    });
  } catch (error) {
    console.error('Unexpected logout error:', error);
    res.status(500).json({ error: 'Unexpected error during logout' });
  }
});

// Basic route
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Add this route before other routes for debugging
app.get('/auth-status', (req, res) => {
  res.json({
    session: req.session,
    user: req.user,
    isAuthenticated: req.isAuthenticated()
  });
});

// Add validation schemas
const registerSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

// Add after existing auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    // Validate request body
    const { error } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with explicit null googleId
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      }
    });

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;

    // Log in the user
    req.login(userWithoutPassword, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Error logging in' });
      }
      return res.json(userWithoutPassword);
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Error creating user' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    // Validate request body
    const { error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { email, password } = req.body;

    // Find user
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user || !user.password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;

    // Log in the user
    req.login(userWithoutPassword, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Error logging in' });
      }
      return res.json(userWithoutPassword);
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Error logging in' });
  }
});

// Shop validation schema
const shopSchema = Joi.object({
  name: Joi.string().required(),
  address: Joi.string().required(),
});

// Shop routes
app.get('/api/shops', async (req, res) => {
  try {
    const shops = await prisma.shop.findMany({
      where: {
        userId: req.user.id
      }
    });
    res.json(shops);
  } catch (error) {
    console.error('Error fetching shops:', error);
    res.status(500).json({ error: 'Error fetching shops' });
  }
});

app.post('/api/shops', async (req, res) => {
  try {
    const { error } = shopSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const shop = await prisma.shop.create({
      data: {
        ...req.body,
        userId: req.user.id
      }
    });
    res.json(shop);
  } catch (error) {
    console.error('Error creating shop:', error);
    res.status(500).json({ error: 'Error creating shop' });
  }
});

app.put('/api/shops/:id', async (req, res) => {
  try {
    const { error } = shopSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const shop = await prisma.shop.update({
      where: {
        id: req.params.id,
        userId: req.user.id
      },
      data: req.body
    });
    res.json(shop);
  } catch (error) {
    console.error('Error updating shop:', error);
    res.status(500).json({ error: 'Error updating shop' });
  }
});

app.delete('/api/shops/:id', async (req, res) => {
  try {
    await prisma.shop.delete({
      where: {
        id: req.params.id,
        userId: req.user.id
      }
    });
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting shop:', error);
    res.status(500).json({ error: 'Error deleting shop' });
  }
});

// Bill validation schema
const billSchema = Joi.object({
  id: Joi.string().optional(),
  shopId: Joi.string().required(),
  number: Joi.string().required(),
  date: Joi.date().required(),
  total: Joi.number().required(),
  gst: Joi.number().required(),
  discount: Joi.number().required(),
  items: Joi.array().items(
    Joi.object({
      description: Joi.string().required(),
      quantity: Joi.number().required(),
      price: Joi.number().required()
    })
  ).required()
});

// Add this after your existing bill routes

// Add this after your imports and before the routes
const authenticateToken = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// Update all bill routes to use authenticateToken middleware

// Create bill
app.post('/api/bills', authenticateToken, async (req, res) => {
  try {
    const { error } = billSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    // Verify shop belongs to user
    const shop = await prisma.shop.findUnique({
      where: {
        id: req.body.shopId,
        userId: req.user.id,
      },
    });

    if (!shop) {
      return res.status(404).json({ error: 'Shop not found' });
    }

    // Create bill with items
    const bill = await prisma.bill.create({
      data: {
        number: req.body.number,
        date: new Date(req.body.date),
        shopId: req.body.shopId,
        total: req.body.total,
        gst: req.body.gst,
        discount: req.body.discount,
        items: {
          create: req.body.items.map(item => ({
            description: item.description,
            quantity: item.quantity,
            price: item.price,
          })),
        },
      },
      include: {
        items: true,
      },
    });

    res.json(bill);
  } catch (error) {
    console.error('Error creating bill:', error);
    res.status(500).json({ error: 'Error creating bill' });
  }
});

// Get bills for a specific shop
app.get('/api/shops/:shopId/bills', authenticateToken, async (req, res) => {
  try {
    const { search, startDate, endDate, minAmount, maxAmount } = req.query;
    
    let whereClause = {
      shopId: req.params.shopId,
      shop: {
        userId: req.user.id,
      }
    };

    if (search) {
      whereClause.OR = [
        { number: { contains: search, mode: 'insensitive' } },
        { items: { some: { description: { contains: search, mode: 'insensitive' } } } }
      ];
    }

    if (startDate) {
      whereClause.date = { ...whereClause.date, gte: new Date(startDate) };
    }

    if (endDate) {
      whereClause.date = { ...whereClause.date, lte: new Date(endDate) };
    }

    if (minAmount) {
      whereClause.total = { ...whereClause.total, gte: parseFloat(minAmount) };
    }

    if (maxAmount) {
      whereClause.total = { ...whereClause.total, lte: parseFloat(maxAmount) };
    }

    const bills = await prisma.bill.findMany({
      where: {
        shopId: req.params.shopId,
        shop: {
          userId: req.user.id,
        }
      },
      include: {
        items: true,
        shop: true,
      },
      orderBy: {
        date: 'desc',
      },
    });

    res.json(bills);
  } catch (error) {
    console.error('Error fetching bills:', error);
    res.status(500).json({ error: 'Error fetching bills' });
  }
});

// Get all bills
app.get('/api/bills', authenticateToken, async (req, res) => {
  try {
    const { search, startDate, endDate, minAmount, maxAmount } = req.query;
    
    // Get all shops owned by the user
    const userShops = await prisma.shop.findMany({
      where: {
        userId: req.user.id
      },
      select: {
        id: true
      }
    });

    const shopIds = userShops.map(shop => shop.id);

    // Build the where clause for filtering
    const whereClause = {
      shopId: {
        in: shopIds
      },
      AND: []
    };

    // Add search filter
    if (search) {
      whereClause.AND.push({
        OR: [
          { number: { contains: search, mode: 'insensitive' } },
          {
            shop: {
              name: { contains: search, mode: 'insensitive' }
            }
          }
        ]
      });
    }

    // Add date range filter
    if (startDate) {
      whereClause.AND.push({
        date: {
          gte: new Date(startDate)
        }
      });
    }

    if (endDate) {
      whereClause.AND.push({
        date: {
          lte: new Date(endDate)
        }
      });
    }

    // Add amount range filter
    if (minAmount) {
      whereClause.AND.push({
        total: {
          gte: parseFloat(minAmount)
        }
      });
    }

    if (maxAmount) {
      whereClause.AND.push({
        total: {
          lte: parseFloat(maxAmount)
        }
      });
    }

    // If no AND conditions, remove the empty AND array
    if (whereClause.AND.length === 0) {
      delete whereClause.AND;
    }

    // Fetch bills with filters
    const bills = await prisma.bill.findMany({
      where: whereClause,
      include: {
        items: true,
        shop: {
          select: {
            name: true,
            address: true
          }
        }
      },
      orderBy: {
        date: 'desc'
      }
    });

    res.json(bills);
  } catch (error) {
    console.error('Error fetching all bills:', error);
    res.status(500).json({ error: 'Error fetching bills' });
  }
});

// Get single bill
app.get('/api/bills/:id', authenticateToken, async (req, res) => {
  try {
    const bill = await prisma.bill.findFirst({
      where: {
        id: req.params.id,
        shop: {
          userId: req.user.id,
        },
      },
      include: {
        items: true,
        shop: true,
      },
    });

    if (!bill) {
      return res.status(404).json({ error: 'Bill not found' });
    }

    res.json(bill);
  } catch (error) {
    console.error('Error fetching bill:', error);
    res.status(500).json({ error: 'Error fetching bill' });
  }
});

// Update bill
app.put('/api/bills/:id', authenticateToken, async (req, res) => {
  try {
    const { error } = billSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    // Verify bill belongs to user's shop
    const existingBill = await prisma.bill.findFirst({
      where: {
        id: req.params.id,
        shop: {
          userId: req.user.id,
        },
      },
    });

    if (!existingBill) {
      return res.status(404).json({ error: 'Bill not found' });
    }

    // Use transaction to ensure data consistency
    const updatedBill = await prisma.$transaction(async (prisma) => {
      // Delete existing items
      await prisma.billItem.deleteMany({
        where: {
          billId: req.params.id,
        },
      });

      // Update bill and create new items
      return prisma.bill.update({
        where: {
          id: req.params.id,
        },
        data: {
          number: req.body.number,
          date: new Date(req.body.date),
          total: parseFloat(req.body.total),
          gst: parseFloat(req.body.gst),
          discount: parseFloat(req.body.discount),
          shopId: req.body.shopId,
          items: {
            create: req.body.items.map(item => ({
              description: item.description,
              quantity: parseInt(item.quantity),
              price: parseFloat(item.price),
            })),
          },
        },
        include: {
          items: true,
          shop: true,
        },
      });
    });

    res.json(updatedBill);
  } catch (error) {
    console.error('Error updating bill:', error);
    res.status(500).json({ error: 'Error updating bill', details: error.message });
  }
});

// Delete bill
app.delete('/api/bills/:id', authenticateToken, async (req, res) => {
  try {
    // Verify bill belongs to user's shop
    const bill = await prisma.bill.findFirst({
      where: {
        id: req.params.id,
        shop: {
          userId: req.user.id,
        },
      },
    });

    if (!bill) {
      return res.status(404).json({ error: 'Bill not found' });
    }

    // First delete all related bill items
    await prisma.billItem.deleteMany({
      where: {
        billId: req.params.id,
      },
    });

    // Then delete the bill
    await prisma.bill.delete({
      where: {
        id: req.params.id,
      },
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting bill:', error);
    res.status(500).json({ error: 'Error deleting bill' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Error handling middleware should be last
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(500).json({ error: 'Authentication failed', details: err.message });
});

// Add this before your routes
app.use((req, res, next) => {
  console.log('Session:', req.session);
  console.log('User:', req.user);
  console.log('Is Authenticated:', req.isAuthenticated());
  next();
}); 