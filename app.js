

const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const socket = require("socket.io");
const bodyParser = require('body-parser');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();

const nodemailer = require('nodemailer');
const crypto = require('crypto');



const port = process.env.PORT || 9000;

const app = express();
const server = http.createServer(app);
const io = socket(server, {
  cors: {
    origin: 'https://chatfrontend-two.vercel.app', // Replace with your frontend's origin
    methods: ['GET', 'POST'],
    credentials: true,
  },
});




const corsOptions = {
  origin: 'https://chatfrontend-two.vercel.app',
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
  optionsSuccessStatus: 204,
};



app.use(cors(corsOptions));

app.use(bodyParser.json());

app.use('/uploads', express.static("uploads"));


const User = require('./schema/usermodal.js');
const Messages = require('./schema/messageModel.js');



const secretKey = process.env.SCRETKEY || "fwnlfbwlfvdwedfn";



mongoose.connect(process.env.MONGOLINK, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});




const authenticateUser = (req, res, next) => {
  const authorizationHeader = req.headers['authorization'];
  
  if (!authorizationHeader) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authorizationHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};


// Set up multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + ext);
  },
});

const upload = multer({ storage: storage });

app.get('/users', authenticateUser, async (req, res) => {
  const userId = req.user.userId;
  const users = await User.find({ _id: { $ne: userId } }, 'username email');
  res.json(users);
});









app.get('/users', async (req, res) => {
  const users = await User.find({}, 'username email');
  res.json(users);
});


global.onlineUsers = new Map();

io.on("connection", (socket) => {
  global.chatSocket = socket;
  socket.on("add-user", (userId) => {
   
    onlineUsers.set(userId, socket.id);
  });

  socket.on("send-msg", (data) => {
    const sendUserSocket = onlineUsers.get(data.to);
     (data.messageInput);
    if (sendUserSocket) {
      
      socket.to(sendUserSocket).emit("msg-recieve", data.messageInput);
    }
  });
});






app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    console.log(user);


    if (!user)
      return res.status(404).json({ msg: 'User not found', status: false });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res
        .status(401)
        .json({ msg: 'Incorrect email or password', status: false });

    return res.json({ status: true, user });
  } catch (ex) {
    next(ex); // Pass the error to the next middleware
  }
});


app.get('/alluser/:id', async (req, res,next) => {

  try {
    const users = await User.find({ _id: { $ne: req.params.id } }).select([
      "email",
      "username",
      "profileImage",
      "_id",
    ]);
    return res.json(users);
  } catch (ex) {
    next(ex);
  }


})

app.post('/getmessages', async (req, res,next) => {

  try {
    const { from, to } = req.body;

    const messages = await Messages.find({
      users: {
        $all: [from, to],
      },
    }).sort({ updatedAt: 1 });

    const projectedMessages = messages.map((msg) => {
      return {
        fromSelf: msg.sender.toString() === from,
        message: msg.message.text,
      };
    });
    res.json(projectedMessages);
  } catch (ex) {
    next(ex);
  }

})



app.post('/messages', async (req, res,next) => {

  try {
    const { from, to, message } = req.body;
    const data = await Messages.create({
      message: { text: message },
      users: [from, to],
      sender: from,
    });

    if (data) return res.json({ msg: "Message added successfully." });
    else return res.json({ msg: "Failed to add message to the database" });
  } catch (ex) {
    next(ex);
  }

})

app.post('/signup', upload.single('profileImage'), async (req, res) => {
  try {
    const { username, email, password } = req.body;

    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    
    const profileImage = req.file ? req.file.filename : null;

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ username, email, password: hashedPassword, profileImage });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, secretKey, { expiresIn: '1h' });

    res.status(201).json({ message: 'User created successfully', token, newUser });
  } catch (error) {
   

    if (error instanceof multer.MulterError) {
      // Multer-related error
      res.status(400).json({ error: 'File upload error' });
    } else if (error.message === 'Invalid file type. Only images are allowed.') {
      // Invalid file type error
      res.status(400).json({ error: error.message });
    } else {
      // Other errors
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
});

server.listen(port, () => {
   (`Server Connection established on  ${port}`);
});

