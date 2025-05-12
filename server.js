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

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const client = new MongoClient(process.env.MONGODB_URI);
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

// MongoDB Connection
let usersCollection;
async function connectDB() {
  try {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    usersCollection = db.collection('Dash');
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('MongoDB connection error:', err);
  }
}
connectDB();

// Middleware to check if user is logged in
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    return next();
  }
  res.redirect('/login');
};

// Middleware to check if user is admin
const isAdmin = async (req, res, next) => {
  if (req.session.user) {
    const user = await usersCollection.findOne({ email: req.session.user.email });
    if (user && user.user_type === 'admin') {
      return next();
    }
    res.status(403).render('error', { error: 'You are not authorized to access this page', status: 403 });
  } else {
    res.redirect('/login');
  }
};

// Routes
app.get('/', (req, res) => {
  if (req.session.user) {
    res.render('home', { loggedIn: true, name: req.session.user.name });
  } else {
    res.render('home', { loggedIn: false });
  }
});

app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

app.post('/signupSubmit', async (req, res) => {
  const { error } = signupSchema.validate(req.body);
  if (error) {
    return res.render('signup', { error: error.details[0].message });
  }

  const { name, email, password } = req.body;

  try {
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.render('signup', { error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    // Set default user_type to 'user'
    await usersCollection.insertOne({
      name,
      email,
      password: hashedPassword,
      user_type: 'user',
    });

    req.session.user = { name, email, user_type: 'user' };
    res.redirect('/members');
  } catch (err) {
    res.render('signup', { error: 'Server error, please try again' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/loginSubmit', async (req, res) => {
  const { error } = loginSchema.validate(req.body);
  if (error) {
    return res.render('login', { error: error.details[0].message });
  }

  const { email, password } = req.body;

  try {
    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.render('login', { error: 'Invalid email/password combination' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render('login', { error: 'Invalid email/password combination' });
    }

    req.session.user = { name: user.name, email: user.email, user_type: user.user_type };
    res.redirect('/members');
  } catch (err) {
    res.render('login', { error: 'Server error, please try again' });
  }
});

app.get('/members', isAuthenticated, (req, res) => {
  // Display all three images in a responsive grid
  const images = ['image1.jpg', 'image2.jpg', 'image3.jpg'];
  res.render('members', {
    name: req.session.user.name,
    images: images.map(img => `/images/${img}`),
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Session destruction error:', err);
    }
    res.redirect('/');
  });
});

app.get('/admin', isAdmin, async (req, res) => {
  try {
    const users = await usersCollection.find({}).toArray();
    res.render('admin', { users });
  } catch (err) {
    res.render('error', { error: 'Server error, please try again', status: 500 });
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
    res.render('error', { error: 'Server error, please try again', status: 500 });
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
    res.render('error', { error: 'Server error, please try again', status: 500 });
  }
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});