require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const socketio = require("socket.io");
const http = require("http");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const jwt = require("jsonwebtoken");

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Enhanced CORS Configuration
const corsOptions = {
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'device-id',
    'Accept',
    'x-access-token'
  ],
  exposedHeaders: ['Authorization', 'x-access-token'],
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400 // 24 hours
};

// Apply security middleware
app.use(helmet());
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '10kb' }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000,
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api', limiter);

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://kspelectronics:saipreetham@cluster0.wun6q.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
  retryWrites: true,
  retryReads: true,
  maxPoolSize: 10,
  family: 4
})
.then(() => console.log("MongoDB Connected Successfully"))
.catch((err) => {
  console.error("MongoDB Connection Error:", err);
  process.exit(1);
});

// Configure Socket.IO
const io = socketio(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    transports: ['websocket', 'polling'],
    allowEIO3: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1d';

// Generate JWT Token
const signToken = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
};

// Global error handler middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    status: 'error',
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Schemas
const userSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  contact: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  ipAddress: { type: String },
  lastLogin: { type: Date },
  role: { type: String, enum: ['user', 'driver', 'admin'], default: 'user' }
});

const busSchema = new mongoose.Schema({
  busNumber: { type: String, required: true, unique: true },
  route: { type: String, required: true },
  driverId: { type: String, required: true },
  currentStatus: { type: String, enum: ['active', 'inactive', 'maintenance'], default: 'active' },
  capacity: { type: Number, default: 40 },
  contactNumber: { type: String },
  lastUpdated: { type: Date }
});

const trackerSchema = new mongoose.Schema({
  deviceId: { type: String, required: true },
  busNumber: { type: String, required: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  speed: { type: Number },
  direction: { type: Number },
  timestamp: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model("User", userSchema);
const Bus = mongoose.model("Bus", busSchema);
const Tracker = mongoose.model("Tracker", trackerSchema);

// Utility functions
const getClientIp = (req) => {
  return req.headers['x-forwarded-for'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null);
};

// Socket.IO Connection Handling
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  socket.on('joinBus', (busNumber) => {
    socket.join(busNumber);
    console.log(`Socket ${socket.id} joined bus ${busNumber}`);
  });

  socket.on('locationUpdate', async (data) => {
    try {
      const { busNumber, latitude, longitude, speed, direction } = data;
      
      const tracker = new Tracker({
        deviceId: socket.id,
        busNumber,
        latitude,
        longitude,
        speed,
        direction
      });
      await tracker.save();

      await Bus.findOneAndUpdate(
        { busNumber },
        { lastUpdated: new Date() },
        { upsert: true }
      );

      io.to(busNumber).emit('busLocation', {
        busNumber,
        latitude,
        longitude,
        speed,
        direction,
        timestamp: new Date()
      });
    } catch (error) {
      console.error('Error handling location update:', error);
      socket.emit('error', { message: 'Failed to update location' });
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// API Routes
app.post("/api/register", async (req, res, next) => {
  try {
    const { userId, name, contact, email, password, confirmPassword, role } = req.body;
    
    if (password !== confirmPassword) {
      return res.status(400).json({
        status: 'fail',
        message: 'Passwords do not match'
      });
    }

    const existingUser = await User.findOne({ $or: [{ userId }, { email }] });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'User ID or Email already exists'
      });
    }

    const ipAddress = getClientIp(req);

    const newUser = await User.create({
      userId,
      name,
      contact,
      email,
      password,
      ipAddress,
      lastLogin: new Date(),
      role: role || 'user'
    });

    // Generate JWT token for the new user
    const token = signToken(newUser.userId);

    res.status(201).json({
      status: 'success',
      token,
      data: {
        user: {
          userId: newUser.userId,
          name: newUser.name,
          email: newUser.email,
          role: newUser.role
        }
      }
    });
  } catch (err) {
    next(err);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const { userId, password } = req.body;

    if (!userId || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide user ID and password!'
      });
    }

    const user = await User.findOne({ userId });
    const ipAddress = getClientIp(req);

    if (!user || password !== user.password) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect user ID or password'
      });
    }

    user.ipAddress = ipAddress;
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = signToken(user.userId);

    res.status(200).json({
      status: 'success',
      token,
      data: {
        user: {
          userId: user.userId,
          name: user.name,
          email: user.email,
          role: user.role,
          ipAddress: user.ipAddress,
          lastLogin: user.lastLogin
        }
      }
    });
  } catch (err) {
    next(err);
  }
});

// Protected routes middleware
const protect = async (req, res, next) => {
  try {
    // 1) Getting token and check if it's there
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }

    // 2) Verification token
    const decoded = jwt.verify(token, JWT_SECRET);

    // 3) Check if user still exists
    const currentUser = await User.findOne({ userId: decoded.id });
    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token does no longer exist.'
      });
    }

    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    next();
  } catch (err) {
    next(err);
  }
};

// Example of a protected route
app.get("/api/me", protect, async (req, res, next) => {
  try {
    res.status(200).json({
      status: 'success',
      data: {
        user: req.user
      }
    });
  } catch (err) {
    next(err);
  }
});

// Bus Management Endpoints
app.post("/api/buses", protect, async (req, res, next) => {
  try {
    const { busNumber, route, driverId, capacity, contactNumber } = req.body;
    
    const bus = await Bus.create({
      busNumber,
      route,
      driverId,
      capacity,
      contactNumber
    });

    res.status(201).json({
      status: 'success',
      data: {
        bus
      }
    });
  } catch (err) {
    next(err);
  }
});

app.get("/api/buses", protect, async (req, res, next) => {
  try {
    const buses = await Bus.find().populate('driverId', 'name contact');
    
    res.status(200).json({
      status: 'success',
      results: buses.length,
      data: {
        buses
      }
    });
  } catch (err) {
    next(err);
  }
});

app.get("/api/buses/:busNumber", protect, async (req, res, next) => {
  try {
    const bus = await Bus.findOne({ busNumber: req.params.busNumber })
      .populate('driverId', 'name contact');
    
    if (!bus) {
      return res.status(404).json({
        status: 'fail',
        message: 'No bus found with that ID'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        bus
      }
    });
  } catch (err) {
    next(err);
  }
});

// Location Tracking Endpoints
app.post("/api/trackers", protect, async (req, res, next) => {
  try {
    const { busNumber, latitude, longitude, speed, direction } = req.body;
    
    if (!busNumber || !latitude || !longitude) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide busNumber, latitude, and longitude'
      });
    }

    if (isNaN(latitude) || isNaN(longitude)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Latitude and longitude must be valid numbers'
      });
    }

    const tracker = await Tracker.create({
      deviceId: req.headers['device-id'] || 'web',
      busNumber,
      latitude: parseFloat(latitude),
      longitude: parseFloat(longitude),
      speed: speed ? parseFloat(speed) : null,
      direction: direction ? parseFloat(direction) : null
    });

    await Bus.findOneAndUpdate(
      { busNumber },
      { lastUpdated: new Date() },
      { upsert: true, new: true }
    );

    io.to(busNumber).emit('busLocation', {
      busNumber,
      latitude: tracker.latitude,
      longitude: tracker.longitude,
      speed: tracker.speed,
      direction: tracker.direction,
      timestamp: tracker.timestamp
    });

    res.status(201).json({
      status: 'success',
      data: {
        tracker: {
          busNumber: tracker.busNumber,
          latitude: tracker.latitude,
          longitude: tracker.longitude,
          speed: tracker.speed,
          direction: tracker.direction,
          timestamp: tracker.timestamp
        }
      }
    });
  } catch (err) {
    next(err);
  }
});

app.get("/api/trackers/:busNumber", protect, async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit) || 1;
    const trackers = await Tracker.find({ busNumber: req.params.busNumber })
      .sort({ timestamp: -1 })
      .limit(limit);

    if (trackers.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'No tracking data found for this bus'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        trackers
      }
    });
  } catch (err) {
    next(err);
  }
});

app.get("/api/trackers/history/:busNumber", protect, async (req, res, next) => {
  try {
    const { startDate, endDate } = req.query;
    const query = { busNumber: req.params.busNumber };

    if (startDate && endDate) {
      query.timestamp = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }

    const trackers = await Tracker.find(query).sort({ timestamp: 1 });
    
    res.status(200).json({
      status: 'success',
      results: trackers.length,
      data: {
        trackers
      }
    });
  } catch (err) {
    next(err);
  }
});

// 404 Handler
app.all('*', (req, res, next) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

server.listen(PORT, HOST, () => {
  console.log(`Server running on http://${HOST}:${PORT}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION! 💥 Shutting down...');
  console.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.error(err.name, err.message);
  process.exit(1);
});