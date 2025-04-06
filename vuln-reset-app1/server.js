const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const port = 3000;

mongoose.connect('mongodb://127.0.0.1:27017/vuln-reset-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  resetToken: String,
  tokenExpire: Date
});

const User = mongoose.model('User', userSchema);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: false }));

app.get('/', (req, res) => {
  res.render('home');
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const existingUser = await User.findOne({ email });

  if (existingUser) {
    return res.send('User already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ name, email, password: hashedPassword });
  await newUser.save();
  
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.send('Invalid email or password');
  }

  res.redirect('/');
});

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.send('Email not found');

  const token = crypto.randomBytes(32).toString('hex');
  user.resetToken = token;
  user.tokenExpire = Date.now() + 3600000;
  await user.save();

  const resetLink = `http://localhost:3000/reset-password/${token}`;
  console.log('Reset link:', resetLink);

  res.send('Password reset link has been sent (check console)');
});

app.get('/reset-password/:token', async (req, res) => {
  const user = await User.findOne({ resetToken: req.params.token });
  if (!user) return res.send('Invalid token');

  res.render('reset-password', { token: req.params.token });
});

app.post('/reset-password/:token', async (req, res) => {
  const { password } = req.body;
  const user = await User.findOne({ resetToken: req.params.token });

  if (!user) return res.send('Invalid token');

  const hashedPassword = await bcrypt.hash(password, 10);
  user.password = hashedPassword;
  await user.save();

  res.send('Password has been reset!');
});

app.listen(port, () => {
  console.log(`App running at http://localhost:${port}`);
});
