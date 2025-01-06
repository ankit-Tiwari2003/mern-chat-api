const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const Message = require('./models/Message');
const ws = require('ws');
const cloudinary = require('cloudinary').v2;
dotenv.config();

// Database connection
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);

const app = express();
app.use(express.json({ limit: '10mb' }));  // Increased limit for base64 files
app.use(cookieParser());
app.use(cors({
  credentials: true,
  origin: process.env.CLIENT_URL,
}));

// Helper function to get user data from JWT token
async function getUserDataFromRequest(req) {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token;
    if (token) {
      jwt.verify(token, jwtSecret, {}, (err, userData) => {
        if (err) reject(err);
        resolve(userData);
      });
    } else {
      reject('no token');
    }
  });
}

// Routes
app.get('/test', (req, res) => {
  res.json('test ok');
});

app.get('/messages/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const userData = await getUserDataFromRequest(req);
    const ourUserId = userData.userId;
    const messages = await Message.find({
      sender: { $in: [userId, ourUserId] },
      recipient: { $in: [userId, ourUserId] },
    }).sort({ createdAt: 1 });
    res.json(messages);
  } catch (err) {
    res.status(401).json('Unauthorized');
  }
});

app.get('/people', async (req, res) => {
  try {
    const users = await User.find({}, { '_id': 1, username: 1 });
    res.json(users);
  } catch (err) {
    res.status(500).json('Error fetching users');
  }
});

app.get('/profile', (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    jwt.verify(token, jwtSecret, {}, (err, userData) => {
      if (err) throw err;
      res.json(userData);
    });
  } else {
    res.status(401).json('no token');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const foundUser = await User.findOne({ username });
    if (foundUser) {
      const passOk = bcrypt.compareSync(password, foundUser.password);
      if (passOk) {
        jwt.sign({ userId: foundUser._id, username }, jwtSecret, {}, (err, token) => {
          if (err) throw err;
          res.cookie('token', token, { sameSite: 'none', secure: true }).json({
            id: foundUser._id,
          });
        });
      } else {
        res.status(401).json('Invalid credentials');
      }
    } else {
      res.status(401).json('User not found');
    }
  } catch (err) {
    res.status(500).json('Error during login');
  }
});

app.post('/logout', (req, res) => {
  res.cookie('token', '', { sameSite: 'none', secure: true }).json('ok');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
    const createdUser = await User.create({
      username: username,
      password: hashedPassword,
    });
    jwt.sign({ userId: createdUser._id, username }, jwtSecret, {}, (err, token) => {
      if (err) throw err;
      res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
        id: createdUser._id,
      });
    });
  } catch (err) {
    if (err.code === 11000) {
      // MongoDB duplicate key error
      res.status(400).json('Username already exists');
    } else {
      res.status(500).json('Error creating user');
    }
  }
});

const server = app.listen(process.env.PORT || 8080, () => {
  console.log('Server started');
});

// WebSocket Server
const wss = new ws.WebSocketServer({ server });

wss.on('connection', (connection, req) => {
  connection.isAlive = true;

  // Keep-alive mechanism
  connection.timer = setInterval(() => {
    connection.ping();
    connection.deathTimer = setTimeout(() => {
      connection.isAlive = false;
      clearInterval(connection.timer);
      connection.terminate();
      notifyAboutOnlinePeople();
    }, 1000);
  }, 5000);

  connection.on('pong', () => {
    clearTimeout(connection.deathTimer);
  });

  // Notify about online users
  function notifyAboutOnlinePeople() {
    [...wss.clients].forEach(client => {
      client.send(JSON.stringify({
        online: [...wss.clients].map(c => ({
          userId: c.userId,
          username: c.username
        })),
      }));
    });
  }

  // Auth: get user from cookie
  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookieString = cookies.split(';').find(str => str.startsWith('token='));
    if (tokenCookieString) {
      const token = tokenCookieString.split('=')[1];
      if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
          if (err) throw err;
          const { userId, username } = userData;
          connection.userId = userId;
          connection.username = username;
        });
      }
    }
  }

  connection.on('message', async (message) => {
    const messageData = JSON.parse(message.toString());
    const { recipient, text, file } = messageData;
    let fileUrl = null;

    if (file) {
      try {
        // Upload to Cloudinary
        const uploadResponse = await cloudinary.uploader.upload(file.data, {
          folder: 'chat_attachments',
          resource_type: 'auto',
          timeout: 60000,
        });
        fileUrl = uploadResponse.secure_url;
      } catch (err) {
        console.error('Cloudinary upload error:', err);
        connection.send(JSON.stringify({
          error: 'Failed to upload file'
        }));
        return;
      }
    }

    if (recipient && (text || fileUrl)) {
      try {
        const messageDoc = await Message.create({
          sender: connection.userId,
          recipient,
          text,
          file: fileUrl,
        });

        // Send message to recipient if online
        [...wss.clients]
          .filter(c => c.userId === recipient)
          .forEach(c => c.send(JSON.stringify({
            text,
            sender: connection.userId,
            recipient,
            file: fileUrl,
            _id: messageDoc._id,
            createdAt: messageDoc.createdAt,
          })));

      } catch (err) {
        console.error('Message creation error:', err);
        connection.send(JSON.stringify({
          error: 'Failed to save message'
        }));
      }
    }
  });

  // Notify about online people when someone connects
  notifyAboutOnlinePeople();
});