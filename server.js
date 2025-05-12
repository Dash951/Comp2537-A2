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
      console.error('Authentication failed. Please check MONGODB_URI credentials in .env or Render environment variables.');
    }
    process.exit(1);
  }
}
connectDB();

// ... (rest of your server.js code remains unchanged)