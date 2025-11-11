const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const path = require('path');
const cors = require('cors');
const socketIo = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Cloudinary konfiguratsiyasi
cloudinary.config({
  cloud_name: 'dh3heagct',
  api_key: '564992594627199',
  api_secret: 'GzOEMTuo7k2bwYQjLqcFXyHOu2A'
});

// Umumiy multer storage Cloudinary bilan
const cloudinaryStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: (req, file) => {
    let folder = 'avatars';
    let allowed_formats = ['jpg', 'png', 'jpeg'];
    let transformations = [];

    if (file.fieldname === 'documents') {
      folder = 'documents';
      allowed_formats = ['pdf', 'jpg', 'jpeg', 'png'];
    } else if (file.fieldname === 'postImage') {
      folder = 'posts';
      transformations = [{ width: 800, height: 600, crop: 'limit' }];
    } else if (file.fieldname === 'avatar') {
      transformations = [{ width: 200, height: 200, crop: 'fill' }];
    }

    return {
      folder,
      allowed_formats,
      transformation: transformations
    };
  }
});

const uploadFields = multer({ storage: cloudinaryStorage }).fields([
  { name: 'avatar', maxCount: 1 },
  { name: 'documents', maxCount: 5 },
  { name: 'postImage', maxCount: 1 }
]);

// MongoDB ulanish
mongoose.connect('mongodb+srv://apl:apl00@gamepaymentbot.ffcsj5v.mongodb.net/med?retryWrites=true&w=majority');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static('public'));

// Modellar
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'lawyer', 'admin'], default: 'user' },
  profile: {
    firstName: String,
    lastName: String,
    avatar: String, // Cloudinary URL
    bio: String,
    phone: String,
    location: String,
    legalSpecialization: String,
    rating: { type: Number, default: 0 },
    successfulCases: { type: Number, default: 0 },
    failedCases: { type: Number, default: 0 },
    documents: [{
      name: String,
      filePath: String, // Cloudinary URL
      verified: { type: Boolean, default: false }
    }],
    isVerified: { type: Boolean, default: false }
  },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const PostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  image: String, // Cloudinary URL
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    replies: [{
      user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      text: String,
      createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
  }],
  shares: { type: Number, default: 0 },
  category: String,
  createdAt: { type: Date, default: Date.now }
});

const ChatSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  messages: [{
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    timestamp: { type: Date, default: Date.now }
  }],
  lastMessage: { type: Date, default: Date.now }
});

const ConsultationSchema = new mongoose.Schema({
  client: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  lawyer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  date: { type: Date, required: true },
  time: String,
  status: { type: String, enum: ['pending', 'confirmed', 'completed', 'cancelled'], default: 'pending' },
  notes: String,
  rating: Number,
  feedback: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Chat = mongoose.model('Chat', ChatSchema);
const Consultation = mongoose.model('Consultation', ConsultationSchema);

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token mavjud emas' });
  }

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token yaroqsiz' });
    }
    req.user = user;
    next();
  });
};

// Admin login middleware (admin role check)
const authenticateAdmin = (req, res, next) => {
  authenticateToken(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Faqat admin uchun ruxsat berilgan' });
    }
    next();
  });
};

// Auth routes
app.post('/api/register', uploadFields, async (req, res) => {
  try {
    const { username, email, password, role, firstName, lastName, phone, location, legalSpecialization } = req.body;
    
    console.log('Register request:', { username, email, role, files: req.files ? Object.keys(req.files) : 'none' }); // Debug log
    
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Foydalanuvchi allaqachon mavjud' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const userData = {
      username,
      email,
      password: hashedPassword,
      role,
      profile: {
        firstName,
        lastName,
        phone,
        location: role === 'lawyer' ? location : undefined,
        legalSpecialization: role === 'lawyer' ? legalSpecialization : undefined
      }
    };

    // Avatar yuklash
    if (req.files && req.files['avatar'] && req.files['avatar'].length > 0) {
      userData.profile.avatar = req.files['avatar'][0].path;
    }

    // Documents yuklash (faqat lawyer uchun)
    if (req.files && req.files['documents'] && req.files['documents'].length > 0 && role === 'lawyer') {
      userData.profile.documents = req.files['documents'].map(file => ({
        name: file.originalname,
        filePath: file.path
      }));
    }

    const user = new User(userData);
    await user.save();

    const token = jwt.sign({ userId: user._id, role: user.role }, 'secret_key');
    res.status(201).json({ token, user: { id: user._id, username: user.username, role: user.role } });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Foydalanuvchi topilmadi' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Noto\'g\'ri parol' });
    }

    const token = jwt.sign({ userId: user._id, role: user.role }, 'secret_key');
    res.json({ token, user: { id: user._id, username: user.username, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

// Post routes (birlashtirilgan: pagination + author support)
app.get('/api/posts', async (req, res) => {
  try {
    const { page = 1, limit = 6, search, category, author } = req.query;
    let query = {};
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { content: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (category) {
      query.category = category;
    }
    
    if (author) {
      query.author = author;
    }
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    let postsQuery = Post.find(query).populate('author', 'username profile.avatar profile.firstName profile.lastName').sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit));
    
    // Agar author bo'lsa va profile postlari bo'lsa, comments ni populate qilish (optimize uchun)
    if (author) {
      postsQuery = postsQuery.populate('comments.user', 'username profile.avatar profile.firstName profile.lastName')
                            .populate('comments.replies.user', 'username profile.avatar profile.firstName profile.lastName');
    }
    
    const posts = await postsQuery;
    
    res.json(posts);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.post('/api/posts', authenticateToken, uploadFields, async (req, res) => {
  try {
    const { title, content, category } = req.body;
    
    const postData = {
      title,
      content,
      author: req.user.userId,
      category
    };

    if (req.files && req.files['postImage'] && req.files['postImage'].length > 0) {
      postData.image = req.files['postImage'][0].path;
    }
    
    const post = new Post(postData);
    await post.save();
    await post.populate('author', 'username profile.avatar profile.firstName profile.lastName');
    
    res.status(201).json(post);
  } catch (error) {
    console.error('Post creation error:', error);
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ message: 'Post topilmadi' });
    }
    
    const likeIndex = post.likes.indexOf(req.user.userId);
    
    if (likeIndex > -1) {
      post.likes.splice(likeIndex, 1);
    } else {
      post.likes.push(req.user.userId);
    }
    
    await post.save();
    res.json({ likes: post.likes.length, isLiked: likeIndex === -1 });
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.post('/api/posts/:id/comment', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ message: 'Post topilmadi' });
    }
    
    post.comments.push({
      user: req.user.userId,
      text
    });
    
    await post.save();
    await post.populate('comments.user', 'username profile.avatar profile.firstName profile.lastName');
    
    const newComment = post.comments[post.comments.length - 1];
    res.json(newComment);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.post('/api/posts/:postId/comment/:commentId/reply', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;
    const post = await Post.findById(req.params.postId);
    
    if (!post) {
      return res.status(404).json({ message: 'Post topilmadi' });
    }
    
    const comment = post.comments.id(req.params.commentId);
    if (!comment) {
      return res.status(404).json({ message: 'Komment topilmadi' });
    }
    
    comment.replies.push({
      user: req.user.userId,
      text
    });
    
    await post.save();
    await post.populate('comments.replies.user', 'username profile.avatar profile.firstName profile.lastName');
    
    const newReply = comment.replies[comment.replies.length - 1];
    res.json(newReply);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

// User routes
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password')
      .populate('followers', 'username profile.avatar profile.firstName profile.lastName')
      .populate('following', 'username profile.avatar profile.firstName profile.lastName');
    
    if (!user) {
      return res.status(404).json({ message: 'Foydalanuvchi topilmadi' });
    }
    
    const postsCount = await Post.countDocuments({ author: user._id });
    
    res.json({
      user,
      postsCount,
      followersCount: user.followers.length,
      followingCount: user.following.length
    });
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.put('/api/users/:id', authenticateToken, uploadFields, async (req, res) => {
  try {
    if (req.user.userId !== req.params.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Ruxsat yo\'q' });
    }
    
    const { firstName, lastName, bio, phone, location, legalSpecialization } = req.body;
    
    const updateData = {
      'profile.firstName': firstName,
      'profile.lastName': lastName,
      'profile.bio': bio,
      'profile.phone': phone,
      'profile.location': location,
      'profile.legalSpecialization': legalSpecialization
    };
    
    if (req.files && req.files['avatar'] && req.files['avatar'].length > 0) {
      updateData['profile.avatar'] = req.files['avatar'][0].path;
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: updateData },
      { new: true }
    ).select('-password');
    
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
  try {
    const userToFollow = await User.findById(req.params.id);
    const currentUser = await User.findById(req.user.userId);
    
    if (!userToFollow) {
      return res.status(404).json({ message: 'Foydalanuvchi topilmadi' });
    }
    
    const isFollowing = currentUser.following.includes(userToFollow._id);
    
    if (isFollowing) {
      currentUser.following.pull(userToFollow._id);
      userToFollow.followers.pull(currentUser._id);
    } else {
      currentUser.following.push(userToFollow._id);
      userToFollow.followers.push(currentUser._id);
    }
    
    await currentUser.save();
    await userToFollow.save();
    
    res.json({ 
      isFollowing: !isFollowing,
      followersCount: userToFollow.followers.length 
    });
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

// Lawyer routes
app.get('/api/lawyers', async (req, res) => {
  try {
    const { legalSpecialization, search } = req.query;
    let query = { role: 'lawyer', 'profile.isVerified': true };
    
    if (legalSpecialization) {
      query['profile.legalSpecialization'] = legalSpecialization;
    }
    
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { 'profile.firstName': { $regex: search, $options: 'i' } },
        { 'profile.lastName': { $regex: search, $options: 'i' } }
      ];
    }
    
    const lawyers = await User.find(query)
      .select('-password')
      .sort({ 'profile.rating': -1 });
    
    res.json(lawyers);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.post('/api/lawyers/:id/verify', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Faqat admin tasdiqlashi mumkin' });
    }
    
    const lawyer = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { 'profile.isVerified': true } },
      { new: true }
    ).select('-password');
    
    res.json(lawyer);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.get('/api/consultations', authenticateToken, async (req, res) => {
  try {
    const { lawyerId, status } = req.query;
    let query = {};
    
    if (status) {
      query.status = status;
    }
    
    if (req.user.role === 'lawyer') {
      query.lawyer = req.user.userId;
    } else if (req.user.role === 'user') {
      query.client = req.user.userId;
    }
    
    // User lawyer consultations ni olish uchun
    if (lawyerId && req.user.role === 'user') {
      query.lawyer = lawyerId;
    }
    
    const consultations = await Consultation.find(query)
      .populate('client', 'username profile.avatar profile.firstName profile.lastName')
      .populate('lawyer', 'username profile.avatar profile.firstName profile.lastName')
      .sort({ date: 1 });
    
    res.json(consultations);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.post('/api/consultations', authenticateToken, async (req, res) => {
  try {
    const { lawyerId, date, time, notes } = req.body;
    
    if (req.user.role !== 'user') {
      return res.status(403).json({ message: 'Faqat mijozlar maslahat buyurtma qilishi mumkin' });
    }
    
    const consultation = new Consultation({
      client: req.user.userId,
      lawyer: lawyerId,
      date,
      time,
      notes
    });
    
    await consultation.save();
    await consultation.populate('client', 'username profile.avatar profile.firstName profile.lastName')
                      .populate('lawyer', 'username profile.avatar profile.firstName profile.lastName');
    
    res.status(201).json(consultation);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.put('/api/consultations/:id', authenticateToken, async (req, res) => {
  try {
    const { status, rating, feedback } = req.body;
    
    const consultation = await Consultation.findById(req.params.id);
    
    if (!consultation) {
      return res.status(404).json({ message: 'Maslahat topilmadi' });
    }
    
    if (req.user.role === 'lawyer' && consultation.lawyer.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Ruxsat yo\'q' });
    }
    
    if (req.user.role === 'user' && consultation.client.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Ruxsat yo\'q' });
    }
    
    if (status) consultation.status = status;
    if (rating) consultation.rating = rating;
    if (feedback) consultation.feedback = feedback;
    
    await consultation.save();
    
    // Agar rating berilgan bo'lsa, lawyer reytingini yangilash
    if (rating) {
      const lawyerConsultations = await Consultation.find({ 
        lawyer: consultation.lawyer, 
        rating: { $exists: true } 
      });
      
      const avgRating = lawyerConsultations.reduce((sum, cons) => sum + cons.rating, 0) / lawyerConsultations.length;
      
      await User.findByIdAndUpdate(consultation.lawyer, {
        $set: { 'profile.rating': avgRating }
      });
    }
    
    // Feedback ga asoslanib successful/failedCases ni yangilash
    if (feedback) {
      const lawyer = await User.findById(consultation.lawyer);
      if (feedback === 'qoniqdim') {
        lawyer.profile.successfulCases += 1;
      } else if (feedback === 'qoniqmadim') {
        lawyer.profile.failedCases += 1;
      }
      await lawyer.save();
    }
    
    res.json(consultation);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

// Chat routes
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const chats = await Chat.find({
      participants: req.user.userId
    })
    .populate('participants', 'username profile.avatar profile.firstName profile.lastName')
    .populate('messages.sender', 'username profile.avatar profile.firstName profile.lastName')
    .sort({ lastMessage: -1 });
    
    res.json(chats);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { participantId } = req.body;
    
    // Chat mavjudligini tekshirish
    let chat = await Chat.findOne({
      participants: { $all: [req.user.userId, participantId] }
    });
    
    if (!chat) {
      chat = new Chat({
        participants: [req.user.userId, participantId]
      });
      
      await chat.save();
    }
    
    await chat.populate('participants', 'username profile.avatar profile.firstName profile.lastName');
    res.json(chat);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

// Chat xabarlarini olish
app.get('/api/chats/:id/messages', authenticateToken, async (req, res) => {
  try {
    const chat = await Chat.findById(req.params.id)
      .populate('messages.sender', 'username profile.avatar profile.firstName profile.lastName');
    
    if (!chat) {
      return res.status(404).json({ message: 'Chat topilmadi' });
    }
    
    // Foydalanuvchi chatda ishtirok etishini tekshirish
    if (!chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ message: 'Ruxsat yo\'q' });
    }
    
    res.json(chat.messages);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

// Chat xabarini yuborish
app.post('/api/chats/:id/messages', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;
    const chat = await Chat.findById(req.params.id);
    
    if (!chat) {
      return res.status(404).json({ message: 'Chat topilmadi' });
    }
    
    // Foydalanuvchi chatda ishtirok etishini tekshirish
    if (!chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ message: 'Ruxsat yo\'q' });
    }
    
    chat.messages.push({
      sender: req.user.userId,
      text
    });
    
    chat.lastMessage = new Date();
    await chat.save();
    
    await chat.populate('messages.sender', 'username profile.avatar profile.firstName profile.lastName');
    
    const newMessage = chat.messages[chat.messages.length - 1];
    res.status(201).json(newMessage);
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

// Admin routes
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const usersCount = await User.countDocuments({ role: 'user' });
    const lawyersCount = await User.countDocuments({ role: 'lawyer' });
    const postsCount = await Post.countDocuments();
    const consultationsCount = await Consultation.countDocuments();
    
    const topLawyers = await User.find({ role: 'lawyer' })
      .select('-password')
      .sort({ 'profile.rating': -1 })
      .limit(10);
    
    const pendingLawyers = await User.find({ 
      role: 'lawyer', 
      'profile.isVerified': false 
    }).select('-password');
    
    res.json({
      usersCount,
      lawyersCount,
      postsCount,
      consultationsCount,
      topLawyers,
      pendingLawyers
    });
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, role } = req.query;
    let query = {};

    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { 'profile.firstName': { $regex: search, $options: 'i' } },
        { 'profile.lastName': { $regex: search, $options: 'i' } }
      ];
    }

    if (role) {
      query.role = role;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const totalUsers = await User.countDocuments(query);

    res.json({
      users,
      totalUsers,
      currentPage: parseInt(page),
      totalPages: Math.ceil(totalUsers / parseInt(limit))
    });
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Post.deleteMany({ author: req.params.id });
    await Consultation.deleteMany({ 
      $or: [{ client: req.params.id }, { lawyer: req.params.id }] 
    });
    
    res.json({ message: 'Foydalanuvchi muvaffaqiyatli o\'chirildi' });
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.delete('/api/admin/posts/:id', authenticateAdmin, async (req, res) => {
  try {
    await Post.findByIdAndDelete(req.params.id);
    res.json({ message: 'Post muvaffaqiyatli o\'chirildi' });
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

app.get('/api/admin/consultations', authenticateAdmin, async (req, res) => {
  try {
    const { status, page = 1, limit = 10 } = req.query;
    let query = {};

    if (status) {
      query.status = status;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const consultations = await Consultation.find(query)
      .populate('client', 'username profile.avatar profile.firstName profile.lastName')
      .populate('lawyer', 'username profile.avatar profile.firstName profile.lastName')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const totalConsultations = await Consultation.countDocuments(query);

    res.json({
      consultations,
      totalConsultations,
      currentPage: parseInt(page),
      totalPages: Math.ceil(totalConsultations / parseInt(limit))
    });
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

// Chatbot API (yuridik maslahatlar)
app.post('/api/chatbot', async (req, res) => {
  try {
    const { message } = req.body;
    
    const responses = {
      'meros masalasi': 'Meros masalasi bo\'yicha O\'zbekiston Fuqarolik Kodeksiga muvofiq harakat qilish tavsiya etiladi. Advokat bilan bog\'laning.',
      'ajralish': 'Ajralish jarayonida oilaviy huquq mutaxassisi bilan maslahatlashing. Sud jarayoni talab qilinishi mumkin.',
      'jinoyat ishi': 'Jinoyat ishida jinoiy huquq advokati kerak. Darhol yordam so\'rang.',
      'shartnoma': 'Shartnoma tuzishda fuqarolik huquqi bo\'yicha maslahat oling.',
      'mehnat nizosi': 'Mehnat nizolarida mehnat huquqi mutaxassisi yordam beradi.'
    };
    
    let response = 'Kechirasiz, savolingizni tushunmadim. Batafsilroq tasvirlab bering yoki boshqa advokatlardan yordam so\'rang.';
    
    for (const [keyword, botResponse] of Object.entries(responses)) {
      if (message.toLowerCase().includes(keyword)) {
        response = botResponse;
        break;
      }
    }
    
    // Advokatlarni taklif qilish
    let recommendedLawyers = [];
    if (message.toLowerCase().includes('meros masalasi')) {
      recommendedLawyers = await User.find({ 
        role: 'lawyer', 
        'profile.legalSpecialization': 'Fuqarolik huquqi',
        'profile.isVerified': true 
      }).select('username profile.avatar profile.firstName profile.lastName profile.rating').limit(3);
    } else if (message.toLowerCase().includes('ajralish')) {
      recommendedLawyers = await User.find({ 
        role: 'lawyer', 
        'profile.legalSpecialization': 'Oilaviy huquq',
        'profile.isVerified': true 
      }).select('username profile.avatar profile.firstName profile.lastName profile.rating').limit(3);
    }
    
    res.json({ response, recommendedLawyers });
  } catch (error) {
    res.status(500).json({ message: 'Server xatosi', error: error.message });
  }
});

// server.js da admin yaratish kodi
const createAdmin = async () => {
  try {
    const adminExists = await User.findOne({ email: 'admin@legal.com' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const admin = new User({
        username: 'admin',
        email: 'admin@legal.com',
        password: hashedPassword,
        role: 'admin',
        profile: {
          firstName: 'System',
          lastName: 'Admin'
        }
      });
      await admin.save();
      console.log('Admin hisobi yaratildi: email - admin@legal.com, parol - admin123');
    } else {
      console.log('Admin hisobi allaqachon mavjud');
    }
  } catch (error) {
    console.error('Admin yaratishda xatolik:', error);
  }
};

// Socket.io for real-time chat
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  
  socket.on('join-chat', (chatId) => {
    socket.join(chatId);
  });
  
  socket.on('send-message', async (data) => {
    try {
      const { chatId, senderId, text } = data;
      
      const chat = await Chat.findById(chatId);
      if (!chat) return;
      
      chat.messages.push({
        sender: senderId,
        text
      });
      
      chat.lastMessage = new Date();
      await chat.save();
      
      io.to(chatId).emit('new-message', {
        sender: senderId,
        text,
        timestamp: new Date()
      });
    } catch (error) {
      console.error('Xabar yuborishda xatolik:', error);
    }
  });
  
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Static file routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register-login.html'));
});

app.get('/index', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/lawyer', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'lawyer.html'));
});

app.get('/chatbot', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'chatbot.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/create', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'create.html'));
});

const PORT = process.env.PORT || 3000;

// Server ishga tushganda admin yaratish
mongoose.connection.once('open', async () => {
  console.log('MongoDB ulandi');
  await createAdmin();
});

server.listen(PORT, () => {
  console.log(`Server ${PORT}-portda ishlamoqda`);
});