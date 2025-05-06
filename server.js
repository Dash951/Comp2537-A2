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

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

const client = new MongoClient(
  `${process.env.MONGODB_HOST}${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`,
  {
    auth: {
      username: process.env.MONGODB_USER,
      password: process.env.MONGODB_PASSWORD,
    },
  }
);

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

const signupSchema = Joi.object({
  name: Joi.string().max(20).required(),
  email: Joi.string().email().max(50).required(),
  password: Joi.string().max(20).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().max(50).required(),
  password: Joi.string().max(20).required(),
});

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

app.get('/', (req, res) => {
  if (req.session.user) {
    res.render('home', { loggedIn: true, name: req.session.user.name });
  } else {
    res.render('home', { loggedIn: false });
  }
});

app.get('/signup', (req, res) => {
  res.render('signup');
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

    await usersCollection.insertOne({ name, email, password: hashedPassword });

    req.session.user = { name, email };
    res.redirect('/members');
  } catch (err) {
    res.render('signup', { error: 'Server error, please try again' });
  }
});

app.get('/login', (req, res) => {
  res.render('login');
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

    req.session.user = { name: user.name, email: user.email };
    res.redirect('/members');
  } catch (err) {
    res.render('login', { error: 'Server error, please try again' });
  }
});

app.get('/members', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }

  const images = ['image1.jpg', 'image2.jpg', 'image3.jpg'];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.render('members', {
    name: req.session.user.name,
    image: `/images/${randomImage}`,
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

app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});