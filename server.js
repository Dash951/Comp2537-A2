require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const { MongoClient } = require('mongodb');
const path = require('path');

const app = express();
const port = process.env.PORT || 3015;

// Validate environment variables
if (!process.env.MONGODB_URI) {
  console.error('Error: MONGODB_URI is not defined in environment variables');
  process.exit(1);
}
if (!process.env.MONGODB_DATABASE) {
  console.error('Error: MONGODB_DATABASE is not defined in environment variables');
  process.exit(1);
}
if (!process.env.NODE_SESSION_SECRET) {
  console.error('Error: NODE_SESSION_SECRET is not defined in environment variables');
  process.exit(1);
}

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// MongoDB Connection
let client;
try {
  client = new MongoClient(process.env.MONGODB_URI);
} catch (err) {
  console.error('Failed to create MongoClient:', err.message);
  process.exit(1);
}

app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
      client,
      dbName: process.env.MONGODB_DATABASE,
      collectionName: 'sessions',
      ttl: 3600,
    }),
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 3600 * 1000 },
  })
);

let usersCollection;
async function connectDB() {
  try {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    usersCollection = db.collection('Dash');
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    if (err.name === 'MongoServerError' && err.message.includes('bad auth')) {
      console.error('Authentication failed. Please verify MONGODB_URI credentials.');
    }
    process.exit(1);
  }
}
connectDB();

// Joi Schemas
const signupSchema = Joi.object({
  name: Joi.string().max(20).required(),
  email: Joi.string().email().max(50).required(),
  password: Joi.string().max(20).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().max(50).required(),
  password: Joi.string().max(20).required(),
});

// Middleware to check if user is logged in
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    return next();
  }
  res.redirect('/login');
};

// Middleware to check if user is admin
const isAdmin = async (req, res, next) => {
  try {
    if (req.session.user) {
      const user = await usersCollection.findOne({ email: req.session.user.email });
      if (user && user.user_type === 'admin') {
        return next();
      }
      res.status(403).render('error', { error: 'You are not authorized to access this page', status: 403, loggedIn: !!req.session.user });
    } else {
      res.redirect('/login');
    }
  } catch (err) {
    console.error('Error in isAdmin middleware:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
};

// Routes
app.get('/', (req, res) => {
  try {
    res.render('home', { loggedIn: !!req.session.user, name: req.session.user ? req.session.user.name : null });
  } catch (err) {
    console.error('Error in / route:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

app.get('/signup', (req, res) => {
  try {
    res.render('signup', { error: null, loggedIn: !!req.session.user });
  } catch (err) {
    console.error('Error in /signup route:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

app.post('/signupSubmit', async (req, res) => {
  try {
    const { error } = signupSchema.validate(req.body);
    if (error) {
      return res.render('signup', { error: error.details[0].message, loggedIn: !!req.session.user });
    }

    const { name, email, password } = req.body;

    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.render('signup', { error: 'Email already exists', loggedIn: !!req.session.user });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await usersCollection.insertOne({
      name,
      email,
      password: hashedPassword,
      user_type: 'user',
    });

    req.session.user = { name, email, user_type: 'user' };
    res.redirect('/members');
  } catch (err) {
    console.error('Error in /signupSubmit route:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

app.get('/login', (req, res) => {
  try {
    res.render('login', { error: null, loggedIn: !!req.session.user });
  } catch (err) {
    console.error('Error in /login route:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

app.post('/loginSubmit', async (req, res) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) {
      return res.render('login', { error: error.details[0].message, loggedIn: !!req.session.user });
    }

    const { email, password } = req.body;

    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.render('login', { error: 'Invalid email/password combination', loggedIn: !!req.session.user });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render('login', { error: 'Invalid email/password combination', loggedIn: !!req.session.user });
    }

    req.session.user = { name: user.name, email: user.email, user_type: user.user_type };
    res.redirect('/members');
  } catch (err) {
    console.error('Error in /loginSubmit route:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

app.get('/members', isAuthenticated, (req, res) => {
  try {
    const images = ['image1.jpg', 'image2.jpg', 'image3.jpg'];
    res.render('members', {
      name: req.session.user.name,
      images: images.map(img => `/images/${img}`),
      loggedIn: true, // User is authenticated
    });
  } catch (err) {
    console.error('Error in /members route:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

app.get('/logout', (req, res) => {
  try {
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err.message);
        return res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: false });
      }
      res.redirect('/');
    });
  } catch (err) {
    console.error('Error in /logout route:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

app.get('/admin', isAdmin, async (req, res) => {
  try {
    const users = await usersCollection.find({}).toArray();
    res.render('admin', { users, loggedIn: true }); // User is authenticated and admin
  } catch (err) {
    console.error('Error in /admin route:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

app.get('/admin/promote/:email', isAdmin, async (req, res) => {
  try {
    await usersCollection.updateOne(
      { email: req.params.email },
      { $set: { user_type: 'admin' } }
    );
    res.redirect('/admin');
  } catch (err) {
    console.error('Error in /admin/promote route:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

app.get('/admin/demote/:email', isAdmin, async (req, res) => {
  try {
    await usersCollection.updateOne(
      { email: req.params.email },
      { $set: { user_type: 'user' } }
    );
    res.redirect('/admin');
  } catch (err) {
    console.error('Error in /admin/demote route:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err.message, err.stack);
  res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
});

// 404 handler
app.use((req, res) => {
  try {
    res.status(404).render('404', { loggedIn: !!req.session.user });
  } catch (err) {
    console.error('Error in 404 handler:', err.message);
    res.status(500).render('error', { error: 'Internal Server Error', status: 500, loggedIn: !!req.session.user });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});