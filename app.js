const express = require('express');
const { client } = require("./index.js")
const path = require('path');
const fs = require('fs');
const yaml = require("js-yaml")
const config = yaml.load(fs.readFileSync('./config.yml', 'utf8'));
const bodyParser = require('body-parser');
const packageFile = require('./package.json');
const axios = require('axios');
const color = require('ansi-colors');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const multer = require('multer');
const session = require('express-session');
const crypto = require('crypto');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const userModel = require('./models/userModel')
const productModel = require('./models/productModel')
const downloadsModel = require('./models/downloadsModel')
const reviewModel = require('./models/reviewModel')
const paymentModel = require('./models/paymentModel')
const settingsModel = require('./models/settingsModel')
const CartSnapshot = require('./models/CartSnapshot');
const statisticsModel = require('./models/statisticsModel')
const DiscountCodeModel = require('./models/discountCodeModel')
const markdownIt = require('markdown-it');
const markdownItContainer = require('markdown-it-container');
const ms = require('parse-duration');
const sharp = require('sharp');
const Discord = require('discord.js');

const md = new markdownIt({
  html: true,
  linkify: true,
  typographer: true
});

const NodeCache = require("node-cache");
const cache = new NodeCache({ stdTTL: 120 });

const utils = require('./utils.js');

const paypalClientInstance = require('./utils/paypalClient');
const paypal = require('@paypal/checkout-server-sdk');

const stripe = require('stripe')(config.Payments.Stripe.secretKey);

const { Client, resources, Webhook } = require('coinbase-commerce-node');
Client.init(config.Payments.Coinbase.ApiKey);
const { Charge } = resources;

const app = express();

// Ensure that the uploads directory exists
const uploadDir = path.join(__dirname, './uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Ensure that the reviews directory exists inside uploads
const reviewsDir = path.join(uploadDir, 'reviews');
if (!fs.existsSync(reviewsDir)) {
    fs.mkdirSync(reviewsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
      cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
      cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

const optimizeImage = async (filePath, outputFilePath) => {
  try {
      const image = sharp(filePath);
      const metadata = await image.metadata();
      
      if (metadata.orientation) {
          image.rotate(); 
      }

      await image
          .resize({ 
              width: null,
              height: null,
              fit: sharp.fit.contain
          })
          .toFormat('webp')
          .webp({ quality: 80 })
          .toFile(outputFilePath);

      console.log(`Successfully optimized: ${filePath}`);
  } catch (error) {
      console.error(`Error optimizing image: ${error.message}`);
      throw error;
  }
};

const connectToMongoDB = async () => {
  try {
    if (config.MongoURI) await mongoose.set('strictQuery', false);

    if (config.MongoURI) {
      await mongoose.connect(config.MongoURI);
    } else {
      throw new Error('[ERROR] MongoDB Connection String is not specified in the config! (MongoURI)');
    }
  } catch (error) {
    console.error('\x1b[31m%s\x1b[0m', `[ERROR] Failed to connect to MongoDB: ${error.message}\n${error.stack}`);

    if (error.message.includes('authentication failed')) {
      await console.error('Authentication failed. Make sure to check if you entered the correct username and password in the connection URL.');
      await process.exit(1)
    } else if (error.message.includes('network error')) {
      await console.error('Network error. Make sure the MongoDB server is reachable and the connection URL is correct.');
      await process.exit(1)
    } else if (error.message.includes('permission denied')) {
      await console.error('Permission denied. Make sure the MongoDB cluster has the necessary permissions to read and write.');
      await process.exit(1)
    } else {
      await console.error('An unexpected error occurred. Check the MongoDB connection URL and credentials.');
      await process.exit(1)
    }
  }
};
connectToMongoDB();

const createSettings = async () => {
let settings = await settingsModel.findOne();
if (!settings) {
  settings = new settingsModel();
  await settings.save();
}
}
createSettings()

if(config?.trustProxy) app.set('trust proxy', 1);

app.use(session({
  secret: config.secretKey,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
      mongoUrl: config.MongoURI,
      ttl: ms(config.SessionExpires),
      autoRemove: 'native'
  }),

  cookie: {
      secure: config.Secure,
      maxAge: ms(config.SessionExpires)
  }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());

let globalSettings = {};

async function loadSettings(req, res, next) {
  try {
      const settings = await settingsModel.findOne();
      if (!settings) return next(new Error('Settings not found'));

      globalSettings = settings;

      res.locals.settings = settings;
      res.locals.config = config;


// Function to convert hex color to RGB
function hexToRgb(hex) {
  hex = hex.replace('#', ''); // Remove the '#' at the start of the hex if present
  let r = parseInt(hex.substring(0, 2), 16);
  let g = parseInt(hex.substring(2, 4), 16);
  let b = parseInt(hex.substring(4, 6), 16);
  return `${r}, ${g}, ${b}`;
}
  const rgbColor = hexToRgb(settings.accentColor);
  res.locals.accentColorRgb = rgbColor;

      req.isStaff = function() {
        if (!req.user || !req.user.id) return false;
        return config.OwnerID.includes(req.user.id);
    };

      res.locals.isStaff = req.isStaff();

      next();
  } catch (err) {
      next(err);
  }
}

app.use(loadSettings);

async function checkBan(req, res, next) {
  if (req.isAuthenticated()) {
    const userId = req.user.id;

    try {
      const existingUser = await userModel.findOne({ discordID: userId });

      if (existingUser && existingUser.banned) {
        // If the user is banned, send the error response
        return res.status(403).render('error', {
          errorMessage: 'Your account has been suspended. If you believe this is a mistake, please contact support for assistance.',
        });
      }
    } catch (error) {
      console.error('Error checking ban status:', error.message);
      return res.status(500).render('error', {
        errorMessage: 'An error occurred while checking your account status. Please try again later.',
      });
    }
  }
  next(); // If the user is not banned or not logged in, continue to the next middleware/route.
}

app.use(checkBan);

function checkStaffAccess(req, res, next) {
  if (req.isStaff()) {
    next();
  } else {
    res.redirect('/');
  }
}

async function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    const now = Date.now();
    const lastUpdated = req.session.lastUpdated || 0;

    if (now - lastUpdated > 300000) {
      try {
        const discordUser = await client.users.fetch(req.user.id);

        req.user.discordUsername = discordUser.username;
        req.user.avatar = discordUser.avatar;

        req.session.passport.user = {
          ...req.session.passport.user,
          discordUsername: req.user.discordUsername,
          avatar: req.user.avatar,
        };

        req.session.lastUpdated = now;

        // Check if the username in the database needs to be updated
        const userInDb = await userModel.findOne({ discordID: req.user.id });
        if (userInDb && userInDb.discordUsername !== discordUser.username) {
          userInDb.discordUsername = discordUser.username;
          await userInDb.save(); 
          console.log(`Updated discordUsername in database for user ${req.user.id}`);
        }
      } catch (error) {
        console.error('Error updating session or database data:', error.message);
      }
    }
    next();
  } else {
    res.redirect('/login');
  }
}



// Middleware to inject console script
app.use((req, res, next) => {
  const send = res.send;
  res.send = function (body) {
      if (typeof body === 'string' && body.includes('</body>')) {
        const UserIds = `${config.OwnerID.join(', ')} (${packageFile.debug.dVersion || "UNKNW"}) (LK ${config.LicenseKey ? config.LicenseKey.slice(0, -10) : "UNKNW"})`;
          const consoleScript = `
          <script>
              (function() {
                  const message = \`
%c
Plex Store is made by Plex Development.
Version: ${packageFile.version}
Buy - https://plexdevelopment.net/products/plexstore
\`,
                  style = \`
font-family: monospace;
font-size: 16px;
color: #5e99ff;
background-color: #1e1e1e;
padding: 10px;
border: 1px solid #00aaff;
\`;

                  console.log(message, style);

                  // Group the user IDs and hide the log using console.groupCollapsed
                  console.groupCollapsed('Debug');
                  console.log('${UserIds}');
                  console.groupEnd();
              })();
          </script>
          `;
          // Inject script just before the closing body tag
          body = body.replace('</body>', consoleScript + '</body>');
      }
      send.call(this, body);
  };
  next();
});


const checkApiKey = (req, res, next) => {
  const apiKey = req.header('x-api-key');
  if (globalSettings.apiEnabled && apiKey && apiKey === globalSettings.apiKey) { 
    return next();
  } else {
    return res.status(403).json({ error: 'INVALID_API_KEY' });
  }
};


const CSRF_TOKEN_LIFETIME = 3600000;
function generateCsrfToken(req, res, next) {
  if (req.session && (!req.session.csrfToken || Date.now() > req.session.csrfTokenExpiresAt)) {
      req.session.csrfToken = crypto.randomBytes(24).toString('hex');
      req.session.csrfTokenExpiresAt = Date.now() + CSRF_TOKEN_LIFETIME;
  }
  res.locals.csrfToken = req.session ? req.session.csrfToken : null;
  next();
}

function csrfProtection(req, res, next) {
  // Skip CSRF protection for webhook and API routes
  if (req.path.startsWith('/api') || req.path === '/webhooks/coinbase') {
      return next();
  }

  if (req.method === 'POST') {
      if (!req.session) {
          return res.status(403).send('Session is required for CSRF protection');
      }
      const token = req.body._csrf || req.query._csrf || req.headers['csrf-token'];
      if (!token || token !== req.session.csrfToken) {
          return res.status(403).send('Invalid CSRF token');
      }
  }
  next();
}

app.use(generateCsrfToken);
app.use(csrfProtection);

md.use(markdownItContainer, 'info')
   .use(markdownItContainer, 'success')
   .use(markdownItContainer, 'warning')
   .use(markdownItContainer, 'danger');

   
app.locals.md = md;

passport.use(new DiscordStrategy(
  {
    clientID: config.clientID,
    clientSecret: config.clientSecret,
    callbackURL: config.callbackURL,
    scope: ['identify', 'email', 'guilds.join'],
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if the user already exists in the database
      let user = await userModel.findOne({ discordID: profile.id });
      let guild = await client.guilds.cache.get(config.GuildID)

      if (!user) {
        // If the user does not exist, create a new user
        user = new userModel({
          discordID: profile.id,
          discordUsername: profile.username,
          email: profile.email
        });

        await user.save();

      // Get the current date information
      const now = new Date();
      const currentYear = now.getFullYear();
      const currentMonthIndex = now.getMonth();

      // Update the statistics
      const stats = await statisticsModel.getStatistics();
      // Find or create the current year statistics
      let yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
      if (!yearlyStats) {
          yearlyStats = {
              year: currentYear,
              months: Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }))
          };
          stats.yearlyStats.push(yearlyStats);
      }

      // Ensure that the months array is correctly initialized
      if (!yearlyStats.months || yearlyStats.months.length !== 12) {
          yearlyStats.months = Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }));
      }

      // Update the monthly statistics for the current month
      yearlyStats.months[currentMonthIndex].userJoins += 1;

      await stats.save();

      }

      // Automatically add the user to your Discord server
      if(config.autoJoinUsers) await guild.members.add(profile.id, { accessToken });

      return done(null, profile);
    } catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});


app.get("/auth/discord", passport.authenticate("discord"));
app.get("/auth/discord/callback", passport.authenticate("discord", { failureRedirect: "/" }), (req, res, next) => {
  res.redirect("/");
});

app.get('/login', (req, res, next) => {
  res.redirect('/auth/discord');
});


app.use('/uploads', (req, res, next) => {
  const allowedExtensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico'];
  const sanitizedPath = req.path.replace(/^\//, '');
  const filePath = path.join(__dirname, 'uploads', sanitizedPath);
  const fileExtension = path.extname(filePath).toLowerCase();

  if (!fs.existsSync(filePath)) {
      if(config.DebugMode) console.error(`Access denied: File does not exist - ${filePath}`);
      return res.status(403).send('Access denied');
  }

  if (fs.statSync(filePath).isDirectory()) {
    if(config.DebugMode) console.error(`Access denied: Requested path is a directory - ${filePath}`);
      return res.status(403).send('Access denied');
  }

  if (allowedExtensions.includes(fileExtension)) {
      return res.sendFile(filePath);
  }

  if(config.DebugMode) console.error(`Access denied: File extension not allowed - ${fileExtension}`);
  res.status(403).send('Access denied: File extension not allowed');
});

// Track total site visits
let visitCounter = 0;
const recentVisitors = new Map();

function trackSiteVisits(req, res, next) {
  if (!req.path.startsWith('/api') && !req.path.includes('static')) {
      const userIp = req.ip || req.connection.remoteAddress;
      const now = Date.now();

      // Only count the visit if the user hasn't been recorded in the last 10 minutes
      if (!recentVisitors.has(userIp) || (now - recentVisitors.get(userIp) > 10 * 60 * 1000)) {
          visitCounter += 1;
          recentVisitors.set(userIp, now);
      }
  }
  next();
}


const uploadsDir = path.join(__dirname, 'uploads');

async function cleanupUploads() {
  fs.readdir(uploadsDir, (err, files) => {
      if (err && config.DebugMode) return console.error(`Unable to read directory: ${err.message}`);

      files.forEach(file => {
          if (file.startsWith('temp-')) {
              const filePath = path.join(uploadsDir, file);
              fs.stat(filePath, (err, stats) => {
                  if (err && config.DebugMode) return console.error(`Unable to get stats for file: ${err.message}`);

                  if (stats.isFile() || stats.isDirectory()) {
                      fs.rm(filePath, { recursive: true, force: true }, (err) => {
                          if (err) {
                            if(config.DebugMode) console.error(`Error deleting file/folder: ${err.message}`);
                          } else {
                             if(config.DebugMode) console.log(`Deleted: ${filePath}`);
                          }
                      });
                  }
              });
          }
      });
  });
}

async function saveVisitsToDatabase() {
  try {
      const statistics = await statisticsModel.findOne() || new statisticsModel();
      statistics.totalSiteVisits += visitCounter;

      const now = new Date();
      const currentYear = now.getFullYear();
      const currentMonthIndex = now.getMonth();

      let yearlyStats = statistics.yearlyStats.find(y => y.year === currentYear);
      if (!yearlyStats) {
          yearlyStats = {
              year: currentYear,
              months: Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }))
          };
          statistics.yearlyStats.push(yearlyStats);
      }

      yearlyStats.months[currentMonthIndex].totalSiteVisits += visitCounter;

      await statistics.save();
      visitCounter = 0;

      // Clear old entries in the recentVisitors map to save memory
      const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
      for (let [ip, time] of recentVisitors) {
          if (time < tenMinutesAgo) {
              recentVisitors.delete(ip);
          }
      }
  } catch (error) {
      console.error('Error saving visit count to the database:', error);
  }
}
app.use(trackSiteVisits);

async function checkExpiredSales() {
  try {
    const products = await productModel.find({
      onSale: true,
      saleEndDate: { $ne: null }
    });
 
    const now = new Date();
 
    // Check each product
    for (const product of products) {
      if (product.saleEndDate < now) {
        // Sale has expired - reset sale fields
        await productModel.findByIdAndUpdate(product._id, {
          onSale: false,
          salePrice: null, 
          saleStartDate: null,
          saleEndDate: null
        });
      }
    }
  } catch (error) {
    console.error('Error checking expired sales:', error);
  }
 }

function performMaintenanceTasks() {
  saveVisitsToDatabase();
  cleanupUploads();
  checkExpiredSales();
 }
 

// Set an interval to save the counter and delete temp files every 5 minutes
setInterval(performMaintenanceTasks, 5 * 60 * 1000);
//


app.get('/', async (req, res, next) => {
  try {
    // Retrieve each cache value separately
    let stats = cache.get('stats');
    let totalUsers = cache.get('totalUsers');
    let totalProducts = cache.get('totalProducts');
    
    if (!stats || !totalUsers || !totalProducts) {
      // Run database queries in parallel
      [stats, totalUsers, totalProducts] = await Promise.all([
        statisticsModel.getStatistics(),
        userModel.countDocuments({}),
        productModel.countDocuments({})
      ]);
      
      // Cache the results
      cache.set('stats', stats);
      cache.set('totalUsers', totalUsers);
      cache.set('totalProducts', totalProducts);
    }
    
    // Fetch random reviews
    const reviews = await reviewModel.aggregate([{ $sample: { size: 3 } }]).exec();

    // Fetch Discord user data in parallel with fallbacks
    const reviewsWithDiscordData = await Promise.all(reviews.map(async (review) => {
      const cachedUser = cache.get(`discordUser_${review.discordID}`);
      if (cachedUser) {
        return {
          ...review,
          discordUsername: cachedUser.username,
          discordAvatar: cachedUser.avatar,
        };
      }
      
      try {
        const discordUser = await client.users.fetch(review.discordID);
        const discordUserData = {
          username: discordUser.username,
          avatar: discordUser.displayAvatarURL({ dynamic: true }),
        };
        
        // Cache the Discord user data
        cache.set(`discordUser_${review.discordID}`, discordUserData);
        
        return {
          ...review,
          discordUsername: discordUserData.username,
          discordAvatar: discordUserData.avatar,
        };
      } catch (error) {
        return {
          ...review,
          discordUsername: 'Unknown User',
          discordAvatar: '/images/default-avatar.png',
        };
      }
    }));
    
    // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }
    
    const currentDate = new Date();
    const currentMonth = currentDate.getMonth();
    const currentYear = currentDate.getFullYear();

    const lastMonth = currentMonth === 0 ? 11 : currentMonth - 1;
    const lastMonthYear = currentMonth === 0 ? currentYear - 1 : currentYear;

    const yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
    const previousYearStats = stats.yearlyStats.find(y => y.year === lastMonthYear);

    const thisMonthStats = yearlyStats?.months[currentMonth] || { totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 };
    const lastMonthStats = previousYearStats?.months[lastMonth] || { totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 };

    res.render('home', {
      user: req.user || null,
      existingUser,
      stats,
      thisMonthStats,
      lastMonthStats,
      totalUsers,
      totalProducts,
      reviews: reviewsWithDiscordData,
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/users/:discordID', checkApiKey, async (req, res) => {
  try {
    const { discordID } = req.params;
    const user = await userModel.findOne({ discordID }).populate('cart', 'name productType').populate('ownedProducts', 'name productType');
    if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND' });

    res.json({
      discordID: user.discordID,
      banned: user.banned,
      email: user.email,
      totalSpent: user.totalSpent,
      joinedAt: user.joinedAt,
      cart: user.cart,
      ownedProducts: user.ownedProducts
    });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post('/api/users/:discordID/addproduct/:urlId', checkApiKey, async (req, res) => {
  try {
    const { discordID, urlId } = req.params;

    const user = await userModel.findOne({ discordID });
    if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND' });

    const product = await productModel.findOne({ urlId });
    if (!product) return res.status(404).json({ error: 'PRODUCT_NOT_FOUND' });

    // Check if the user already owns the product
    if (user.ownedProducts.includes(product._id)) return res.status(400).json({ error: 'PRODUCT_ALREADY_OWNED' });
    // Add the product to the user's owned products
    user.ownedProducts.push(product._id);

    const discordUser = await client.users.fetch(user.discordID);

    // Save the updated user and product
    await user.save();

    const guild = await client.guilds.fetch(config.GuildID);
    if (guild && discordUser) {
        try {
            const guildMember = await guild.members.fetch(user.discordID);
    
            if (guildMember) {
                // Check if the product has associated Discord roles to assign
                if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                    for (const roleId of product.discordRoleIds) {
                        // Validate the role ID and ensure the role exists in the guild
                        const role = guild.roles.cache.get(roleId);
                        if (role) {
                            // Add the role to the guild member
                            await guildMember.roles.add(role);
                        } else {
                            if(config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                        }
                    }
                }
            } else {
                if(config.DebugMode) console.warn(`Guild member with ID ${user.discordID} could not be found.`);
            }
        } catch (error) {
            if(config.DebugMode) console.error(`Failed to fetch the guild member or add roles: ${error.message}`);
        }
    } else {
        if(config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
    }

    utils.sendDiscordLog('Product Added to User',`**[API Endpoint]** has added the product \`${product.name}\` to [${discordUser.username}](${config.baseURL}/profile/${user.discordID})'s owned products.`);

    res.json({
      message: 'PRODUCT_ADDED_SUCCESSFULLY',
      user: {
        discordID: user.discordID,
        ownedProducts: user.ownedProducts,
      },
      product: {
        name: product.name,
        urlId: product.urlId,
      },
    });
  } catch (error) {
    console.error('Error adding product to user:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post('/api/users/:discordID/removeproduct/:urlId', checkApiKey, async (req, res) => {
  try {
    const { discordID, urlId } = req.params;

    // Find the user by Discord ID
    const user = await userModel.findOne({ discordID });
    if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND' });

    // Find the product by urlId
    const product = await productModel.findOne({ urlId });
    if (!product) return res.status(404).json({ error: 'PRODUCT_NOT_FOUND' });

    // Check if the user owns the product
    const productIndex = user.ownedProducts.indexOf(product._id);
    if (productIndex === -1) {
      return res.status(400).json({ error: 'PRODUCT_NOT_OWNED' });
    }

    // Remove the product from the user's owned products
    user.ownedProducts.splice(productIndex, 1);

    const discordUser = await client.users.fetch(user.discordID);

    // Save the updated user
    await user.save();

    const guild = await client.guilds.fetch(config.GuildID);
    if (guild && discordUser) {
      try {
          const guildMember = await guild.members.fetch(user.discordID);
  
          if (guildMember) {
              // Check if the product has associated Discord roles to assign
              if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                  for (const roleId of product.discordRoleIds) {
                      // Validate the role ID and ensure the role exists in the guild
                      const role = guild.roles.cache.get(roleId);
                      if (role) {
                          // Add the role to the guild member
                          await guildMember.roles.remove(role);
                      } else {
                          if(config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                      }
                  }
              }
          } else {
              if(config.DebugMode) console.warn(`Guild member with ID ${user.discordID} could not be found.`);
          }
      } catch (error) {
          if(config.DebugMode) console.error(`Failed to fetch the guild member or remove roles: ${error.message}`);
      }
  } else {
      if(config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
  }

    utils.sendDiscordLog('Product Removed from User',`**[API Endpoint]** has removed the product \`${product.name}\` from [${discordUser.username}](${config.baseURL}/profile/${user.discordID})'s owned products.`);

    res.json({
      message: 'PRODUCT_REMOVED_SUCCESSFULLY',
      user: {
        discordID: user.discordID,
        ownedProducts: user.ownedProducts,
      },
      product: {
        name: product.name,
        urlId: product.urlId,
      },
    });
  } catch (error) {
    console.error('Error removing product from user:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});


app.get('/api/payments/:transactionID', checkApiKey, async (req, res) => {
  try {
    const { transactionID } = req.params;
    const payment = await paymentModel.findOne({ transactionID });

    if (!payment) return res.status(404).json({ error: 'PAYMENT_NOT_FOUND' });

    res.json(payment);
  } catch (error) {
    console.error('Error fetching payment data:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/api/products', checkApiKey, async (req, res) => {
  try {
    const products = await productModel.find({}, 'name productType price totalPurchases totalEarned totalDownloads createdAt');

    if (products.length === 0) return res.status(404).json({ error: 'NO_PRODUCTS_FOUND' });

    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});


app.get('/api/statistics', checkApiKey, async (req, res) => {
  try {
    const statistics = await statisticsModel.findOne({}, 'totalPurchases totalEarned totalSiteVisits');

    if (!statistics) return res.status(404).json({ error: 'STATISTICS_NOT_FOUND' });

    const totalUsers = await userModel.countDocuments({});
    const totalProducts = await productModel.countDocuments({});

    res.json({
      totalPurchases: statistics.totalPurchases,
      totalEarned: statistics.totalEarned,
      totalSiteVisits: statistics.totalSiteVisits,
      totalUsers: totalUsers,
      totalProducts: totalProducts
    });
  } catch (error) {
    console.error('Error fetching statistics:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/api/reviews', checkApiKey, async (req, res) => {
  try {
    const reviews = await reviewModel.find({}).select('discordID productName rating comment createdAt');

    if (reviews.length === 0) return res.status(404).json({ error: 'NO_REVIEWS_FOUND' });

    res.json(reviews);
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/tos', async(req, res, next) => {

  if(!req.user) return res.render('tos', { user: null, existingUser: null })

  const existingUser = await userModel.findOne({ discordID: req.user.id });
  res.render('tos', { user: req.user, existingUser })
});

app.get('/privacy-policy', async(req, res, next) => {

  if(!req.user) return res.render('privacy-policy', { user: null, existingUser: null })

  const existingUser = await userModel.findOne({ discordID: req.user.id });
  res.render('privacy-policy', { user: req.user, existingUser })
});

app.get('/staff/overview', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    const stats = await statisticsModel.getStatistics();
    const totalUsers = await userModel.countDocuments();

    // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }

    // Get the current and previous month
    const currentMonth = new Date().getMonth();
    const previousMonth = currentMonth === 0 ? 11 : currentMonth - 1;

    // Get the current and previous year (handle December to January rollover)
    const currentYear = new Date().getFullYear();
    const previousYear = currentMonth === 0 ? currentYear - 1 : currentYear;

    // Get stats for the current and previous months
    const yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
    const previousYearlyStats = stats.yearlyStats.find(y => y.year === previousYear);

    const thisMonthStats = yearlyStats?.months[currentMonth] || { totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 };
    const lastMonthStats = previousMonth === 11 
        ? previousYearlyStats?.months[previousMonth] || { totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 } 
        : yearlyStats?.months[previousMonth] || { totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 };

    // Calculate percentage differences
    const salesDifference = lastMonthStats.totalPurchases === 0 
        ? 100 
        : ((thisMonthStats.totalPurchases - lastMonthStats.totalPurchases) / lastMonthStats.totalPurchases) * 100;

    const joinsDifference = lastMonthStats.userJoins === 0 
        ? 100 
        : ((thisMonthStats.userJoins - lastMonthStats.userJoins) / lastMonthStats.userJoins) * 100;

    const revenueDifference = lastMonthStats.totalEarned === 0 
        ? 100 
        : ((thisMonthStats.totalEarned - lastMonthStats.totalEarned) / lastMonthStats.totalEarned) * 100;
    const visitsDifference = lastMonthStats.totalSiteVisits === 0 
        ? 100 
        : ((thisMonthStats.totalSiteVisits - lastMonthStats.totalSiteVisits) / lastMonthStats.totalSiteVisits) * 100;

    // Prepare data for the chart
    const monthlyUserJoins = yearlyStats?.months.map(m => m.userJoins.toLocaleString('en-US')) || Array(12).fill(0);
    const monthlyPurchases = yearlyStats?.months.map(m => m.totalPurchases) || Array(12).fill(0);
    const monthlyRevenue = yearlyStats?.months.map(m => m.totalEarned.toFixed(2)) || Array(12).fill(0);
    const monthlySiteVisits = yearlyStats?.months.map(m => m.totalSiteVisits.toLocaleString('en-US')) || Array(12).fill(0);

    // Fetch top users by totalSpent
    const topUsers = await userModel.find().sort({ totalSpent: -1 }).limit(5).select('discordUsername totalSpent');

    // Fetch top products by totalPurchases
    const topProducts = await productModel.find().sort({ totalPurchases: -1 }).limit(5).select('name totalPurchases');

    res.render('staff/overview', {
      user: req.user,
      existingUser,
      stats,
      thisMonthStats,
      lastMonthStats,
      salesDifference,
      revenueDifference,
      joinsDifference,
      visitsDifference,
      totalUsers,
      monthlyUserJoins,
      monthlySiteVisits,
      monthlyPurchases,
      monthlyRevenue,
      topUsers,
      topProducts
    });
  } catch (error) {
    next(error);
  }
});



app.get('/staff/anti-piracy', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {

        // Cache the existingUser data
        let existingUser = null;
        if (req.user) {
          existingUser = cache.get(`existingUser_${req.user.id}`);
          if (!existingUser) {
            existingUser = await userModel.findOne({ discordID: req.user.id });
            cache.set(`existingUser_${req.user.id}`, existingUser);
          }
        }

    res.render('staff/anti-piracy', { user: req.user, existingUser, downloadInfo: null });
  } catch (error) {
    console.error('Error fetching anti-piracy-placeholders:', error);
    next(error);
  }
});

app.post('/staff/anti-piracy', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {
    let settings = await settingsModel.findOne();

    settings.antiPiracyEnabled = req.body.antiPiracyEnabled === 'true';

    await settings.save();

    utils.sendDiscordLog('Settings Edited', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has edited the anti-piracy placeholder settings`);

    res.redirect('/staff/anti-piracy');
  } catch (error) {
    console.error('Error saving anti-piracy placeholder:', error);
    next(error);
  }
});

app.get('/staff/anti-piracy/find', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    const { nonce } = req.query;
    if (!nonce) return res.status(400).json({ error: 'Nonce is required.' });

    const downloadInfo = await downloadsModel.findOne({ nonce });
    
    if (downloadInfo) {
      const user = await client.users.fetch(downloadInfo.discordUserId);

      const downloadInfoObj = downloadInfo.toObject();
      downloadInfoObj.discordUsername = user.username;

      res.json({ downloadInfo: downloadInfoObj });
    } else {
      res.json({ downloadInfo: null });
    }
  } catch (error) {
    console.error('Error fetching download by nonce:', error);
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

app.get('/staff/products', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {

        // Cache the existingUser data
        let existingUser = null;
        if (req.user) {
          existingUser = cache.get(`existingUser_${req.user.id}`);
          if (!existingUser) {
            existingUser = await userModel.findOne({ discordID: req.user.id });
            cache.set(`existingUser_${req.user.id}`, existingUser);
          }
        }

    const products = await productModel.find().sort({ position: 1 });

    res.render('staff/products', { user: req.user, existingUser, products });
  } catch (error) {
    console.error('Error fetching products:', error);
    next(error);
  }
});

app.post('/staff/products/sort', checkAuthenticated, checkStaffAccess, async (req, res) => {
  try {
      const { productOrder } = req.body;

      if (!Array.isArray(productOrder)) {
          console.error("Invalid product order format:", productOrder);
          return res.status(400).json({ success: false, message: 'Invalid product order.' });
      }

      for (let i = 0; i < productOrder.length; i++) {
          await productModel.updateOne(
              { _id: productOrder[i] },
              { $set: { position: i + 1 } }
          );
      }

      res.json({ success: true, message: 'Product positions updated.' });
  } catch (error) {
      console.error('Error updating product positions:', error);
      res.status(500).json({ success: false, message: 'An error occurred while updating product positions.' });
  }
});

app.get('/staff/products/create', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
        // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }

    const guild = await client.guilds.fetch(config.GuildID);
    
    // Fetch the bot's member object to find its highest role
    const botMember = await guild.members.fetch(client.user.id);
    const botHighestRole = botMember.roles.highest;

    const roles = guild.roles.cache
      .filter(role => 
        role.position < botHighestRole.position && 
        role.name !== '@everyone' && 
        !role.managed
      )
      .sort((a, b) => b.position - a.position)
      .map(role => ({
        id: role.id,
        name: role.name
      }));

    res.render('staff/create-product', { user: req.user, existingUser, roles });
  } catch (error) {
    next(error);
  }
});

app.post('/staff/products/delete/:id', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {

    const productId = req.params.id;
    const product = await productModel.findById(productId);
    await utils.sendDiscordLog('Product Deleted', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has deleted the product \`${product.name}\``);
    await productModel.findByIdAndDelete(productId);

    await userModel.updateMany(
      { 
        $or: [
          { cart: productId },
          { ownedProducts: productId }
        ]
      },
      { 
        $pull: { 
          cart: productId,
          ownedProducts: productId
        }
      }
    );

    res.redirect('/staff/products')
  } catch (error) {
    next(error);
  }
});

app.post('/staff/products/create', checkAuthenticated, checkStaffAccess, upload.fields([{ name: 'productFile' }, { name: 'bannerImage' }]), csrfProtection, async (req, res, next) => {
  try {
      const { name, description, price, productType, urlId, position, dependencies, discordRoleIds, category, serviceMessage, serialKeys, enableFileUpload } = req.body;

      // Validate URL ID (already ensured by HTML pattern attribute)
      const sanitizedUrlId = urlId.replace(/[^a-zA-Z0-9-]/g, '');

      const bannerImageTempPath = req.files.bannerImage[0].path;
      const bannerImageOptimizedPath = path.join('uploads', Date.now() + '.webp');

      // Optimize and convert the banner image to WebP
      await optimizeImage(bannerImageTempPath, bannerImageOptimizedPath);

      let serialsArray = [];
      if (productType === 'serials' && serialKeys) {
          // Split by newlines and filter out empty lines
          serialsArray = serialKeys.split('\n')
              .map(key => key.trim())
              .filter(key => key !== '')  // Exclude empty lines
              .map(key => ({ key }));     // Convert each key to object format
      }

      let initialVersion = null;
      if ((productType !== 'serials' && productType !== 'service') || 
          (productType === 'serials' && enableFileUpload && req.files.productFile)) {
          initialVersion = {
              version: "First release",
              changelog: "Initial release",
              productFile: req.files.productFile[0].path,
              originalFileName: req.files.productFile[0].originalname,
          };
      }

      // Create a new product instance
      const newProduct = new productModel({
          name,
          description,
          price: productType === 'digitalFree' ? 0 : parseFloat(price),
          productType,
          serviceMessage: productType === 'service' ? serviceMessage : undefined,
          urlId: sanitizedUrlId,
          position: parseInt(position, 10),
          bannerImage: bannerImageOptimizedPath,
          dependencies: dependencies,
          discordRoleIds: Array.isArray(discordRoleIds) ? discordRoleIds : [],
          versions: initialVersion ? [initialVersion] : [],
          category: category || '',
          serials: serialsArray,
          serialRequiresFile: productType === 'serials' ? !!enableFileUpload : undefined
      });

      await newProduct.save();

      utils.sendDiscordLog('Product Created', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has created the product \`${name}\``);

      res.redirect('/staff/products');
  } catch (error) {
      console.error('Error creating product:', error);
      next(error);
  }
});

app.get('/staff/sales', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {
    const products = await productModel.find().sort({ position: 1 });
    const existingUser = await userModel.findOne({ discordID: req.user.id });

    const activeSales = products.filter(product => product.onSale);

    res.render('staff/sales', { 
      user: req.user, 
      products, 
      existingUser, 
      activeSales,
    });
  } catch (error) {
    console.error('Error fetching products for sales:', error);
    next(error);
  }
});

app.post('/staff/sales', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res) => {
  try {
      const { startDate, endDate, productIds, discounts } = req.body;

      if (!startDate || !endDate) return res.status(400).send('Start Date and End Date are required.');

      const saleStartDate = new Date(startDate);
      const saleEndDate = new Date(endDate);

      if (saleStartDate >= saleEndDate) return res.status(400).send('Start Date must be before End Date.');

      // Reset sale data for all products
      await productModel.updateMany({}, {
          $set: { onSale: false, salePrice: null, saleStartDate: null, saleEndDate: null }
      });

      // Update sale details for selected products
      if (productIds && Array.isArray(productIds)) {
          for (const productId of productIds) {
              const discount = parseFloat(discounts[productId]) || 0;
              const product = await productModel.findById(productId);

              if (product) {
                  const salePrice = product.price - (product.price * (discount / 100));
                  product.onSale = true;
                  product.salePrice = salePrice;
                  product.saleStartDate = saleStartDate;
                  product.saleEndDate = saleEndDate;

                  await product.save();
              }
          }
      }

      res.redirect('/staff/sales');
  } catch (error) {
      console.error('Error saving sale details:', error);
      res.status(500).send('Internal Server Error');
  }
});

app.post('/staff/sales/disable', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res) => {
  try {
    const { productId } = req.body;

    if (!productId) return res.status(400).send('Product ID is required.');

    // Disable sale for the specific product
    await productModel.findByIdAndUpdate(productId, {
      $set: { onSale: false, salePrice: null, saleStartDate: null, saleEndDate: null }
    });

    res.redirect('/staff/sales');
  } catch (error) {
    console.error('Error disabling sale:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/staff/products/update/:id', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {
      const productId = req.params.id;
    // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }

      const product = await productModel.findById(productId);
      if (!product) return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });

      res.render('staff/update-product', { user: req.user, existingUser, product });
  } catch (error) {
      console.error('Error loading update product page:', error);
      next(error);
  }
});

app.get('/downloads/:urlId', checkAuthenticated, async (req, res, next) => {
  try {
      const urlId = req.params.urlId;
      const existingUser = await userModel.findOne({ discordID: req.user.id });

      const product = await productModel.findOne({ urlId });
      if (!product) return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });

      // Allow download for free products without ownership check
      if (product.productType === 'digitalFree') {
          // Sort versions by releaseDate in descending order
          product.versions.sort((a, b) => b.releaseDate - a.releaseDate);

          return res.render('downloads', { user: req.user, product, existingUser });
      }

      // Filter out invalid or non-existent products from ownedProducts
      const validOwnedProducts = await productModel.find({_id: { $in: existingUser.ownedProducts.filter(id => id) }}).select('_id'); // Only select _id for the comparison

      // Check if the user owns the product
      const ownsProduct = validOwnedProducts.some(validProduct => validProduct._id.toString() === product._id.toString());
      if (!ownsProduct && !req.isStaff()) return res.redirect('/');

      // Sort versions by releaseDate in descending order
      product.versions.sort((a, b) => b.releaseDate - a.releaseDate);

      res.render('downloads', { user: req.user, product, existingUser });
  } catch (error) {
      console.error('Error loading download page:', error);
      next(error);
  }
});

app.post('/downloads/:urlId/delete/:versionId', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
      const { urlId, versionId } = req.params;

      const product = await productModel.findOne({ urlId });
      if (!product) return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });

      // Find the version to delete
      const versionIndex = product.versions.findIndex(version => version._id.toString() === versionId);
      if (versionIndex === -1) return res.status(404).send('Version not found');

      // Remove the version from the versions array
      product.versions.splice(versionIndex, 1);

      // Save the updated product
      await product.save();

      res.redirect(`/downloads/${urlId}`);
  } catch (error) {
      console.error('Error deleting version:', error);
      next(error);
  }
});

app.get('/downloads/:urlId/download/:versionId', checkAuthenticated, async (req, res, next) => {
  try {
      const { urlId, versionId } = req.params;

      // Find the product by its URL ID
      const product = await productModel.findOne({ urlId });
      if (!product) return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });

      let generatedNonce = await utils.generateNonce()

      const replacements = {
        USER: req.user.id,
        PRODUCT: product.name,
        NONCE: generatedNonce,
        PLEXSTORE: 'true'
      };

      // Find the version to download
      const version = product.versions.id(versionId);
      if (!version) return res.status(404).send('Version not found');

        // Increment the download count for the version
        version.downloadCount = (version.downloadCount || 0) + 1;
        product.totalDownloads = (product.totalDownloads || 0) + 1;
        await product.save();

      // Allow download for free products without ownership check
      if (product.productType === 'digitalFree') {
          if (globalSettings.antiPiracyEnabled) {
              // Process the file with placeholders for free products
              const processedFilePath = await utils.processFileWithPlaceholders(version.productFile, replacements);

              // Save the download information to the downloadsModel
              await downloadsModel.create({
                  productName: product.name,
                  discordUserId: req.user.id,
                  nonce: replacements.NONCE,
                  downloadDate: new Date()
              });

              return res.download(processedFilePath, version.originalFileName, (err) => {
                  if (err) next(err);
              });
          } else {
              // If anti-piracy is not enabled, just download the file
              return res.download(version.productFile, version.originalFileName);
          }
      }

      const existingUser = await userModel.findOne({ discordID: req.user.id });

      // Filter out invalid or non-existent products from ownedProducts
      const validOwnedProducts = await productModel.find({_id: { $in: existingUser.ownedProducts.filter(id => id) }}).select('_id'); // Only select _id for the comparison

      // Check if the user owns the product
      const ownsProduct = validOwnedProducts.some(validProduct => validProduct._id.toString() === product._id.toString());
      if (!ownsProduct && !req.isStaff()) return res.redirect('/');

      if (globalSettings.antiPiracyEnabled) {
          // Process the file with placeholders for paid products
          const processedFilePath = await utils.processFileWithPlaceholders(version.productFile, replacements);

          // Save the download information to the downloadsModel
          await downloadsModel.create({
              productName: product.name,
              discordUserId: req.user.id,
              nonce: generatedNonce,
              downloadDate: new Date()
          });

          return res.download(processedFilePath, version.originalFileName, (err) => {
              if (err) next(err);
          });
      } else {
          // If anti-piracy is not enabled, just download the file
          return res.download(version.productFile, version.originalFileName);
      }

  } catch (error) {
      console.error('Error downloading version:', error);
      next(error);
  }
});


app.post('/staff/products/update/:id', checkAuthenticated, checkStaffAccess, upload.single('productFile'), csrfProtection, async (req, res, next) => {
  try {
      const productId = req.params.id;
      const { version, changelog } = req.body;

      const product = await productModel.findById(productId);
      if (!product) return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });

      // Add new version details
      if (req.file) {
          const newVersion = {
              version: version,
              changelog: changelog,
              productFile: req.file.path,
              originalFileName: req.file.originalname,
              releaseDate: new Date(),
          };

          product.versions.push(newVersion);
      // Automatically delete old versions if enabled in config
      if (config.productVersions.autoDeleteOldFiles) {
        const maxVersionsToKeep = config.productVersions.maxVersionsToKeep;

        // Check if the number of versions exceeds the limit
        while (product.versions.length > maxVersionsToKeep) {
          const oldestVersion = product.versions.shift(); // Remove the first (oldest) version
          
          if(config.DebugMode) console.log(`Deleted old version: ${oldestVersion.version}`);
          
          // delete the file from the storage
          try {
            fs.unlinkSync(oldestVersion.productFile); // Delete the file
            if(config.DebugMode) console.log(`File deleted: ${oldestVersion.productFile}`);
          } catch (err) {
            if(config.DebugMode) console.error(`Failed to delete file: ${oldestVersion.productFile}`, err);
          }
        }
      }
    }

      await product.save();

      utils.sendDiscordLog('Product Updated', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has updated the product \`${product.name}\` \`to ${version}\``);

      res.redirect('/staff/products');
  } catch (error) {
      console.error('Error updating product:', error);
      next(error);
  }
});

app.get('/staff/products/edit/:id', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    const existingUser = await userModel.findOne({ discordID: req.user.id });

      const product = await productModel.findById(req.params.id);
      if (!product) return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });

      const guild = await client.guilds.fetch(config.GuildID);
    
      // Fetch the bot's member object to find its highest role
      const botMember = await guild.members.fetch(client.user.id);
      const botHighestRole = botMember.roles.highest;
  
      const roles = guild.roles.cache
      .filter(role => 
        role.position < botHighestRole.position && 
        role.name !== '@everyone' && 
        !role.managed
      )
      .sort((a, b) => b.position - a.position)
      .map(role => ({
        id: role.id,
        name: role.name
      }));

      res.render('staff/edit-product', { user: req.user, product, existingUser, roles });
  } catch (err) {
      console.error(err);
      next(err);
  }
});

app.post('/staff/products/edit/:id', checkAuthenticated, checkStaffAccess, upload.fields([{ name: 'bannerImage' }, { name: 'productFile' }]), csrfProtection, async (req, res, next) => {
  try {
      const { 
          name, urlId, description, price, productType, position, 
          dependencies, discordRoleIds, category, hideProduct, 
          pauseSelling, serviceMessage, serialKeys, enableFileUpload
      } = req.body;

      let serialsArray = [];
      if (productType === 'serials' && serialKeys) {
          // Split by newlines and filter out empty lines
          serialsArray = serialKeys.split('\n')
              .map(key => key.trim())
              .filter(key => key !== '')
              .map(key => ({ key }));
      }

      const updateData = {
          name,
          urlId,
          description,
          price: productType === 'digitalFree' ? 0 : price,
          productType,
          serviceMessage: productType === 'service' ? serviceMessage : undefined,
          position,
          dependencies,
          discordRoleIds: Array.isArray(discordRoleIds) ? discordRoleIds : [],
          category: category || '',
          hideProduct: !!hideProduct,
          pauseSelling: !!pauseSelling,
          serials: productType === 'serials' ? serialsArray : [],
          serialRequiresFile: productType === 'serials' ? !!enableFileUpload : undefined
      };

      if (req.files['bannerImage']) {
          const originalBannerPath = req.files['bannerImage'][0].path;
          const optimizedBannerPath = path.join('uploads', `${Date.now()}.webp`);

          try {
              await optimizeImage(originalBannerPath, optimizedBannerPath);
              updateData.bannerImage = optimizedBannerPath;
          } catch (error) {
              console.error(`Error optimizing banner image: ${error.message}`);
              throw new Error('Failed to optimize the banner image');
          }
      }

      if (req.files['productFile'] && productType !== 'serials' && productType !== 'service') {
          updateData.productFile = req.files['productFile'][0].path;
      }

      const product = await productModel.findByIdAndUpdate(req.params.id, updateData, { new: true });
      if (!product) {
          return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });
      }

      utils.sendDiscordLog('Product Edited', 
          `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has edited the product \`${name}\`` +
          (productType === 'serials' ? ` (${serialsArray.length} serial keys)` : '')
      );

      res.redirect('/staff/products');
  } catch (error) {
      console.error(error);
      next(error);
  }
});


app.get('/staff/discount-codes', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {

        // Cache the existingUser data
        let existingUser = null;
        if (req.user) {
          existingUser = cache.get(`existingUser_${req.user.id}`);
          if (!existingUser) {
            existingUser = await userModel.findOne({ discordID: req.user.id });
            cache.set(`existingUser_${req.user.id}`, existingUser);
          }
        }

    const codes = await DiscountCodeModel.find();

    res.render('staff/discount-codes', { user: req.user, codes, existingUser });
  } catch (error) {
    console.error('Error fetching discount codes:', error);
    next(error);
  }
});

app.post('/staff/discount-codes/delete/:id', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {

    await DiscountCodeModel.findByIdAndDelete(req.params.id);

    res.redirect('/staff/discount-codes');
  } catch (error) {
    console.error('Error deleting discount code:', error);
    next(error);
  }
});

app.get('/staff/discount-codes/create', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  if (!req.user) {
      return res.redirect('/login');
  }
      // Cache the existingUser data
      let existingUser = null;
      if (req.user) {
        existingUser = cache.get(`existingUser_${req.user.id}`);
        if (!existingUser) {
          existingUser = await userModel.findOne({ discordID: req.user.id });
          cache.set(`existingUser_${req.user.id}`, existingUser);
        }
      }

  res.render('staff/create-discount-code', { user: req.user, existingUser });
});

app.post('/staff/discount-codes/create', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {

      const { name, discountPercentage, maxUses, expiresAt } = req.body;

      const existingCode = await DiscountCodeModel.findOne({ name, _id: { $ne: req.params.id } });
      if (existingCode) return res.status(404).render('error', { errorMessage: 'The discount code name is already in use. Please choose a different name.' });

      // Create new discount code
      const newDiscountCode = new DiscountCodeModel({
          name: name,
          discountPercentage: discountPercentage,
          maxUses: maxUses ? parseInt(maxUses, 10) : null,
          expiresAt: expiresAt ? new Date(expiresAt) : null,
      });

      await newDiscountCode.save();

      utils.sendDiscordLog('Discount Created', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has created the discount \`${name}\``);

      res.redirect('/staff/discount-codes');
  } catch (error) {
      console.error('Error creating discount code:', error);
      next(error);
  }
});

app.get('/staff/discount-codes/edit/:id', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
      const discountCode = await DiscountCodeModel.findById(req.params.id);

      if (!discountCode) return res.status(404).send('Discount code not found.');

      let existingUser = null;
      if (req.user) {
          existingUser = cache.get(`existingUser_${req.user.id}`);
          if (!existingUser) {
              existingUser = await userModel.findOne({ discordID: req.user.id });
              cache.set(`existingUser_${req.user.id}`, existingUser);
          }
      }

      res.render('staff/edit-discount-code', { user: req.user, existingUser, discountCode });
  } catch (error) {
      console.error('Error fetching discount code:', error);
      next(error);
  }
});

app.post('/staff/discount-codes/edit/:id', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {
      const { name, discountPercentage, maxUses, expiresAt } = req.body;

      const existingCode = await DiscountCodeModel.findOne({ name, _id: { $ne: req.params.id } });
      if (existingCode) return res.status(404).render('error', { errorMessage: 'The discount code name is already in use. Please choose a different name.' });

      const discountCode = await DiscountCodeModel.findById(req.params.id);
      if (!discountCode) return res.status(404).send('Discount code not found.');

      // Update discount code fields
      discountCode.name = name;
      discountCode.discountPercentage = discountPercentage;
      discountCode.maxUses = maxUses ? parseInt(maxUses, 10) : null;
      discountCode.expiresAt = expiresAt ? new Date(expiresAt) : null;

      await discountCode.save();

      utils.sendDiscordLog('Discount Edited', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has edited the discount \`${name}\``);

      res.redirect('/staff/discount-codes');
  } catch (error) {
      console.error('Error updating discount code:', error);
      next(error);
  }
});

app.post('/api/discounts/create', checkApiKey, async (req, res) => {
  try {
    const { name, discountPercentage, maxUses, expiresAt } = req.body;

    // Check if a discount code with the same name already exists
    const existingCode = await DiscountCodeModel.findOne({ name });
    if (existingCode) return res.status(400).json({ error: 'DISCOUNT_CODE_ALREADY_EXISTS' });

    // Create the new discount code
    const newDiscountCode = new DiscountCodeModel({
      name: name,
      discountPercentage: discountPercentage,
      maxUses: maxUses ? parseInt(maxUses, 10) : null,
      expiresAt: expiresAt ? new Date(expiresAt) : null,
    });

    // Save the new discount code
    await newDiscountCode.save();

    res.json({
      message: 'DISCOUNT_CODE_CREATED_SUCCESSFULLY',
      discountCode: {
        name: newDiscountCode.name,
        discountPercentage: newDiscountCode.discountPercentage,
        maxUses: newDiscountCode.maxUses,
        expiresAt: newDiscountCode.expiresAt,
      },
    });
  } catch (error) {
    console.error('Error creating discount code:', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/staff/users', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    const existingUser = await userModel.findOne({ discordID: req.user.id });

    const page = parseInt(req.query.page) || 1;
    const limit = 10; 
    const skip = (page - 1) * limit;
    const search = req.query.search || '';
    const sortBy = req.query.sortBy || 'joinedAt';
    const sortOptions = { [sortBy]: sortBy === 'totalSpent' ? -1 : 1 };

    const searchCriteria = search
      ? {
          $or: [
            { discordUsername: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
            { discordID: { $regex: search, $options: 'i' } }
          ]
        }
      : {};

    const totalUsers = await userModel.countDocuments(searchCriteria);
    const users = await userModel.find(searchCriteria).sort(sortOptions).skip(skip).limit(limit);

    const usersWithDiscordData = await Promise.all(users.map(async (user) => {
      const cachedDiscordUser = cache.get(`discordUser_${user.discordID}`);
      if (cachedDiscordUser) {
        return {
          ...user.toObject(),
          discordUsername: cachedDiscordUser.username,
          discordAvatar: cachedDiscordUser.avatar
        };
      }
      try {
        const discordUser = await client.users.fetch(user.discordID);
        const discordUserData = {
          username: discordUser.username,
          avatar: `https://cdn.discordapp.com/avatars/${user.discordID}/${discordUser.avatar}.webp?size=64`
        };
        cache.set(`discordUser_${user.discordID}`, discordUserData);
        return {
          ...user.toObject(),
          discordUsername: discordUserData.username,
          discordAvatar: discordUserData.avatar
        };
      } catch (error) {
        return {
          ...user.toObject(),
          discordUsername: 'Unknown User',
          discordAvatar: '/images/default-avatar.png'
        };
      }
    }));

    res.render('staff/users', {
      user: req.user,
      users: usersWithDiscordData,
      existingUser,
      totalPages: Math.ceil(totalUsers / limit),
      currentPage: page,
      search,
      sortBy
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    next(error);
  }
});



app.get('/staff/settings', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    let settings = await settingsModel.findOne();

    // Fetch Discord channels
    const guild = await client.guilds.fetch(config.GuildID);
    const discordChannels = guild.channels.cache
      .filter(channel => channel.type === 0)
      .map(channel => ({
        id: channel.id,
        name: channel.name,
      }));

    res.render('staff/settings', { user: req.user,  existingUser: req.user, settings, discordChannels });
  } catch (error) {
    console.error('Error fetching settings:', error);
    next(error);
  }
});

app.post('/staff/settings', checkAuthenticated, checkStaffAccess, upload.fields([{ name: 'logo' }, { name: 'backgroundImage' }, { name: 'favicon' }]), csrfProtection, async (req, res, next) => {
  try {

    let settings = await settingsModel.findOne();

    // Update text-based settings
    settings.termsOfService = req.body.termsOfService;
    settings.privacyPolicy = req.body.privacyPolicy;
    settings.aboutUsText = req.body.aboutUsText;
    settings.aboutUsVisible = req.body.aboutUsVisible === 'true';
    settings.displayStats = req.body.displayStats === 'true';
    settings.displayReviews = req.body.displayReviews === 'true';
    settings.displayProductReviews = req.body.displayProductReviews === 'true';
    settings.displayCTABanner = req.body.displayCTABanner === 'true';
    settings.backgroundGradient = req.body.backgroundGradient === 'true';
    settings.displayFeatures = req.body.displayFeatures === 'true';
    settings.accentColor = req.body.accentColor || settings.accentColor;
    settings.discordInviteLink = req.body.discordInviteLink || settings.discordInviteLink;
    settings.salesTax = req.body.salesTax || settings.salesTax;
    settings.siteBannerText = req.body.siteBannerText;
    settings.storeName = req.body.storeName || settings.storeName;
    settings.paymentCurrency = req.body.paymentCurrency || settings.paymentCurrency;
    settings.discordLoggingChannel = req.body.discordLoggingChannel || settings.discordLoggingChannel;

    // Review settings
    settings.sendReviewsToDiscord = req.body.sendReviewsToDiscord === 'true';
    settings.discordReviewChannel = req.body.discordReviewChannel || '';
    settings.minimumReviewLength = parseInt(req.body.minimumReviewLength) || 30;
    settings.allowReviewDeletion = req.body.allowReviewDeletion === 'true';

    // SEO Settings
    settings.seoTitle = req.body.seoTitle || settings.seoTitle;
    settings.seoDescription = req.body.seoDescription || settings.seoDescription;
    settings.seoTags = req.body.seoTags || settings.seoTags;

    // API Settings
    settings.apiEnabled = req.body.apiEnabled === 'true';
    if (req.body.apiKey) {
      settings.apiKey = req.body.apiKey;
    }

    // Automatically set the currency symbol based on the selected currency
    const currencySymbols = {
      USD: '$',    // United States Dollar
      EUR: '€',    // Euro
      GBP: '£',    // British Pound Sterling
      JPY: '¥',    // Japanese Yen
      AUD: 'A$',   // Australian Dollar
      CAD: 'C$',   // Canadian Dollar
      CHF: 'CHF',  // Swiss Franc
      CNY: '¥',    // Chinese Yuan
      SEK: 'kr',   // Swedish Krona
      NZD: 'NZ$',  // New Zealand Dollar
      SGD: 'S$',   // Singapore Dollar
      HKD: 'HK$',  // Hong Kong Dollar
      NOK: 'kr',   // Norwegian Krone
      KRW: '₩',    // South Korean Won
      TRY: '₺',    // Turkish Lira
      RUB: '₽',    // Russian Ruble
      INR: '₹',    // Indian Rupee
      BRL: 'R$',   // Brazilian Real
      ZAR: 'R',    // South African Rand
      MYR: 'RM',   // Malaysian Ringgit
      THB: '฿',    // Thai Baht
      PLN: 'zł',   // Polish Zloty
      PHP: '₱',    // Philippine Peso
      HUF: 'Ft',   // Hungarian Forint
      CZK: 'Kč',   // Czech Koruna
      ILS: '₪',    // Israeli New Shekel
      DKK: 'kr',   // Danish Krone
      AED: 'د.إ',  // United Arab Emirates Dirham
    };
    settings.currencySymbol = currencySymbols[settings.paymentCurrency];

    // Handle file uploads
    if (req.files.logo) {
      settings.logoPath = '/' + req.files['logo'][0].path.replace(/\\/g, '/');
    }
    if (req.files.favicon) {
      settings.faviconPath = '/' + req.files['favicon'][0].path.replace(/\\/g, '/');
    }
    if (req.files.backgroundImage) {
      const backgroundImageTempPath = req.files.backgroundImage[0].path;
      const backgroundImageOptimizedPath = path.join('uploads', Date.now() + '.webp');

      // Optimize and convert the background image to WebP using the optimizeImage function
      await optimizeImage(backgroundImageTempPath, backgroundImageOptimizedPath);

      settings.backgroundImagePath = '/' + backgroundImageOptimizedPath.replace(/\\/g, '/');
    }

        // Update categories
        if (req.body.categories) {
          const categories = JSON.parse(req.body.categories);
          settings.productCategories = categories.map(category => ({
              name: category.name,
              url: category.url,
          }));
      }

    await settings.save();

    utils.sendDiscordLog('Settings Edited', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has edited the store settings`);

    res.redirect('/staff/settings');
  } catch (error) {
    console.error('Error saving settings:', error);
    next(error);
  }
});

app.get('/staff/page-customization', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
    let settings = await settingsModel.findOne();

    res.render('staff/page-customization', { user: req.user, existingUser: req.user, settings });
  } catch (error) {
    console.error('Error fetching settings:', error);
    next(error);
  }
});

app.post('/staff/page-customization', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
  try {
    let settings = await settingsModel.findOne();

    // Page text customization
    settings.homePageTitle = req.body.homePageTitle;
    settings.homePageSubtitle = req.body.homePageSubtitle;
    settings.productsPageTitle = req.body.productsPageTitle;
    settings.productsPageSubtitle = req.body.productsPageSubtitle;
    settings.reviewsPageTitle = req.body.reviewsPageTitle;
    settings.reviewsPageSubtitle = req.body.reviewsPageSubtitle;

    settings.privacyPolicyPageTitle = req.body.privacyPolicyPageTitle;
    settings.privacyPolicyPageSubtitle = req.body.privacyPolicyPageSubtitle;

    settings.tosPageTitle = req.body.tosPageTitle;
    settings.tosPageSubtitle = req.body.tosPageSubtitle;

    settings.websiteFont = req.body.fontSelector;

    settings.customNavTabs = req.body.customNavTabs || [];
    settings.customFooterTabs =  req.body.customFooterTabs || [];
    settings.footerDescription = req.body.footerDescription;

    if (req.body.features && Array.isArray(req.body.features)) {
      settings.features = req.body.features.map(feature => ({
        icon: feature.icon,
        title: feature.title,
        description: feature.description
      }));
    }

    await settings.save();

    utils.sendDiscordLog('Settings Edited', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has edited the page customization settings`);

    res.redirect('/staff/page-customization');
  } catch (error) {
    console.error('Error saving settings:', error);
    next(error);
  }
});

app.get('/products', async (req, res, next) => {
  try {

const products = await productModel
  .find({
    $or: [{ hideProduct: false }, { hideProduct: { $exists: false } }],
  })
  .sort({
    position: 1
  });

    // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }

      res.render('products', { user: req.user, products, existingUser });
  } catch (error) {
      console.error('Error fetching products:', error);
      next(error);
  }
});

app.get('/api/cart/count', async (req, res) => {
  try {
    if (!req.user) {
      return res.json({ count: 0 }); // No user, cart is empty
    }

    const user = await userModel.findOne({ discordID: req.user.id });
    const cartCount = user?.cart?.length || 0;

    res.json({ count: cartCount });
  } catch (error) {
    console.error('Error fetching cart count:', error);
    res.status(500).json({ count: 0 });
  }
});

app.get('/products/category/:category', async (req, res, next) => {
  try {
    const category = req.params.category;

    const products = await productModel.find({ category, $or: [{ hideProduct: false }, { hideProduct: { $exists: false } }] }).sort({ position: 1 });

    // Cache the existingUser data
    let existingUser = null;
    if (req.user) {
      existingUser = cache.get(`existingUser_${req.user.id}`);
      if (!existingUser) {
        existingUser = await userModel.findOne({ discordID: req.user.id });
        cache.set(`existingUser_${req.user.id}`, existingUser);
      }
    }

    res.render('products', { user: req.user, products, existingUser });
  } catch (error) {
    console.error('Error fetching products by category:', error);
    next(error);
  }
});

app.get('/products/:urlId', async (req, res, next) => {
  try {

    const product = await productModel.findOne({ urlId: req.params.urlId });
    if (!product) return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });

    const reviews = await reviewModel
    .find({ product: new mongoose.Types.ObjectId(product._id) })
    .sort({ createdAt: -1 })
    .lean();

  // Fetch Discord user data for each review with caching
  const reviewsWithDiscordData = await Promise.all(
    reviews.map(async (review) => {
      const cachedDiscordUser = cache.get(`discordUser_${review.discordID}`);

      if (cachedDiscordUser) {
        return {
          ...review,
          discordUsername: cachedDiscordUser.username,
          discordAvatar: cachedDiscordUser.avatar,
        };
      }

      try {
        const discordUser = await client.users.fetch(review.discordID);
        const discordUserData = {
          username: discordUser.username,
          avatar: discordUser.displayAvatarURL({ dynamic: true }),
        };

        // Cache the Discord user data
        cache.set(`discordUser_${review.discordID}`, discordUserData);

        return {
          ...review,
          discordUsername: discordUserData.username,
          discordAvatar: discordUserData.avatar,
        };
      } catch (error) {
        return {
          ...review,
          discordUsername: review.discordUsername || 'Unknown User',
          discordAvatar: review.discordAvatarLocalPath || '/images/default-avatar.png',
        };
      }
    })
  );

    if(!req.user) return res.render('view-product', { user: null, product, existingUser: null, reviews: reviewsWithDiscordData });
    const existingUser = await userModel.findOne({ discordID: req.user.id });

      // Filter out invalid product IDs and ensure that the products exist
      if (existingUser && existingUser.ownedProducts) {
        const validOwnedProducts = [];
        
        for (const productId of existingUser.ownedProducts) {
          if (productId) { // Check that productId is not null
            const validProduct = await productModel.findById(productId);
            if (validProduct) {
              validOwnedProducts.push(productId);
            }
          }
        }
        
        existingUser.ownedProducts = validOwnedProducts;
      }

      res.render('view-product', { user: req.user, product, existingUser, reviews: reviewsWithDiscordData, });
  } catch (error) {
      console.error(error);
      next(error);
  }
});

app.post('/cart/add/:productId', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const user = await userModel.findOne({ discordID: req.user.id });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const product = await productModel.findById(req.params.productId);
    if (!product) {
      return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });
    }

    // Check if product is a serial product and out of stock
    if (product.productType === 'serials' && product.serials.length === 0) {
      return res.redirect('/cart');
    }

    // Check if the product is already in the cart
    if (!user.cart.includes(product._id)) {
      user.cart.push(product._id);
      await user.save();
    }

    return res.redirect('/cart');
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.post('/cart/remove/:productId', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const user = await userModel.findOne({ discordID: req.user.id });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const productIndex = user.cart.indexOf(req.params.productId);

    // Check if the product is in the cart
    if (productIndex > -1) {
      user.cart.splice(productIndex, 1); // Remove the product from the cart
      await user.save();
    }

    // Redirect back to the cart page
    return res.redirect('/cart');
  } catch (error) {
    console.error(error);
    next(error);
  }
});


app.get('/cart', checkAuthenticated, async (req, res, next) => {
  try {
    const existingUser = await userModel.findOne({ discordID: req.user.id });
    const user = await userModel.findOne({ discordID: req.user.id }).populate('cart');

    // Clear discount-related session variables
    req.session.discountCode = null;

    if (!user || !user.cart || user.cart.length === 0) {
      return res.render('cart', { 
        user: req.user, 
        cartProducts: [], 
        subtotal: 0, 
        totalPrice: 0, 
        discountApplied: false, 
        discountError: null,
        discountAmount: 0,
        discountPercentage: 0,
        existingUser
      });
    }

    // Filter out out-of-stock serial products
    const updatedCart = [];
    let cartModified = false;
    
    for (const product of user.cart) {
      // Since cart is populated, we can check the product directly
      if (product.productType === 'serials' && (!product.serials || product.serials.length === 0)) {
        cartModified = true;
        continue; // Skip adding this product to updatedCart
      }
      
      updatedCart.push(product._id); // Keep this product in cart
    }

    // Save changes if any products were removed
    if (cartModified) {
      user.cart = updatedCart;
      await user.save();
      
      // Re-fetch products after modification
      const validProducts = await productModel.find({ _id: { $in: updatedCart } });
      
      const currentDate = new Date();
      let subtotal = 0;
      const cartProducts = validProducts.map(product => {
        const isOnSale = product.onSale && 
                        product.saleStartDate <= currentDate && 
                        currentDate <= product.saleEndDate;
        const price = isOnSale ? product.salePrice : product.price;
        subtotal += price;
        return {
          ...product.toObject(),
          effectivePrice: price,
        };
      });

      // Calculate sales tax if applicable
      let salesTaxAmount = 0;
      if (globalSettings.salesTax) {
        salesTaxAmount = parseFloat((subtotal * (globalSettings.salesTax / 100)).toFixed(2));
      }

      // Calculate the total price including sales tax
      const totalPrice = parseFloat((subtotal + salesTaxAmount).toFixed(2));

      return res.render('cart', { 
        user: req.user, 
        cartProducts,
        subtotal: parseFloat(subtotal.toFixed(2)),
        totalPrice,
        salesTaxAmount,
        discountApplied: false, 
        discountError: null,
        discountAmount: 0,
        discountPercentage: 0,
        existingUser,
      });
    }

    // If cart wasn't modified, use the populated products directly
    const currentDate = new Date();
    let subtotal = 0;
    const cartProducts = user.cart.map(product => {
      const isOnSale = product.onSale && 
                      product.saleStartDate <= currentDate && 
                      currentDate <= product.saleEndDate;
      const price = isOnSale ? product.salePrice : product.price;
      subtotal += price;
      return {
        ...product.toObject(),
        effectivePrice: price,
      };
    });

    // Calculate sales tax if applicable
    let salesTaxAmount = 0;
    if (globalSettings.salesTax) {
      salesTaxAmount = parseFloat((subtotal * (globalSettings.salesTax / 100)).toFixed(2));
    }

    // Calculate the total price including sales tax
    const totalPrice = parseFloat((subtotal + salesTaxAmount).toFixed(2));

    res.render('cart', { 
      user: req.user, 
      cartProducts,
      subtotal: parseFloat(subtotal.toFixed(2)),
      totalPrice,
      salesTaxAmount,
      discountApplied: false, 
      discountError: null,
      discountAmount: 0,
      discountPercentage: 0,
      existingUser,
    });
  } catch (error) {
    console.error('Cart error:', error);
    next(error);
  }
});




app.post('/checkout/apply-discount', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const discountCode = req.body.discountCode.toLowerCase();
    const existingUser = await userModel.findOne({ discordID: req.user.id });

    const code = await DiscountCodeModel.findOne({
      name: {
        $regex: new RegExp(`^${discountCode}$`, 'i'),
      },
    });

    const user = await userModel.findOne({ discordID: req.user.id }).populate('cart');

    if (!user) {
      return res.status(404).render('cart', {
        user: req.user,
        cartProducts: [],
        subtotal: 0,
        totalPrice: 0,
        discountError: 'User not found',
        discountApplied: false,
        discountAmount: 0,
        salesTaxAmount: 0,
        discountPercentage: 0,
        existingUser,
      });
    }

    const currentDate = new Date();

    // Check if the cart contains any products on sale
    const hasOnSaleProduct = user.cart.some((product) => {
      return (
        product.onSale &&
        product.saleStartDate <= currentDate &&
        currentDate <= product.saleEndDate
      );
    });

    // Calculate subtotal using `salePrice` when applicable
    const subtotal = user.cart.reduce((acc, product) => {
      const isOnSale =
        product.onSale &&
        product.saleStartDate <= currentDate &&
        currentDate <= product.saleEndDate;
      return acc + (isOnSale ? product.salePrice : product.price);
    }, 0);

    // Calculate the original total before any discounts
    let salesTaxAmountBeforeDiscount = globalSettings.salesTax
      ? parseFloat((subtotal * globalSettings.salesTax / 100).toFixed(2))
      : 0;
    const originalTotal = parseFloat((subtotal + salesTaxAmountBeforeDiscount).toFixed(2)); // Save this for display

    // Initialize default values for discounts
    let discountAmount = 0;
    let discountApplied = false;
    let discountPercentage = 0;
    let discountError = null;

    // Validate discount code
    if (!code) {
      discountError = 'Invalid discount code';
    } else if (code.expiresAt && code.expiresAt < new Date()) {
      discountError = 'This discount code has expired';
    } else if (code.maxUses && code.uses >= code.maxUses) {
      discountError = 'This discount code has reached its maximum uses';
    } else if (hasOnSaleProduct) {
      discountError = 'Discount codes cannot be applied when the cart contains on-sale products.'
    } else {
      // Apply valid discount
      discountPercentage = code.discountPercentage;
      discountAmount = parseFloat((subtotal * discountPercentage / 100).toFixed(2));
      discountApplied = true;
    }

    // Calculate discounted subtotal
    const discountedSubtotal = subtotal - discountAmount;

    // Calculate sales tax on discounted subtotal
    let salesTaxAmount = globalSettings.salesTax
      ? parseFloat((discountedSubtotal * globalSettings.salesTax / 100).toFixed(2))
      : 0;

    // Calculate total price after discount and tax
    const totalPrice = parseFloat((discountedSubtotal + salesTaxAmount).toFixed(2));

    // Store the discount code in the session
    if (discountApplied) {
      req.session.discountCode = discountCode;
    } else {
      req.session.discountCode = null;
    }

    return res.render('cart', {
      user: req.user,
      cartProducts: user.cart,
      subtotal,
      totalPrice,
      originalTotal,
      discountApplied,
      discountError,
      discountAmount,
      discountPercentage,
      salesTaxAmount,
      existingUser,
    });
  } catch (error) {
    console.error(error);
    next(error);
  }
});


app.post('/checkout/paypal', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const user = await userModel.findOne({ discordID: req.user.id }).populate('cart');
    if (!user || !user.cart.length) {
      console.error('[DEBUG] User has no items in the cart.');
      return res.status(400).send('Cart is empty');
    }

    let subtotal = 0;
    const items = [];
    const cartSnapshotItems = [];

    if (config.DebugMode) console.log('[DEBUG] Starting to calculate items and subtotal.');

    // Calculate subtotal and prepare PayPal items
    const currentDate = new Date();

    for (const cartItem of user.cart) {
      const product = await productModel.findById(cartItem._id);
    
      if (!product) {
        if (config.DebugMode) console.warn(`[DEBUG] Product with ID ${cartItem._id} not found. Skipping.`);
        continue; // Skip invalid products
      }
    
      // Determine the effective price
      const isOnSale =
        product.onSale &&
        product.saleStartDate <= currentDate &&
        currentDate <= product.saleEndDate;
      const salePrice = isOnSale ? product.salePrice : null;
      const validPrice = isOnSale ? product.salePrice : product.price;
    
      const validName = product.name?.trim() || 'Unnamed Item'; // Fallback for missing/empty name
      subtotal += validPrice;
    
      if (config.DebugMode) console.log(`[DEBUG] Adding item: ${validName}, Price: ${validPrice.toFixed(2)}`);
    
      items.push({
        name: validName,
        unit_amount: {
          currency_code: globalSettings.paymentCurrency,
          value: validPrice.toFixed(2),
        },
        quantity: '1',
      });
    
      cartSnapshotItems.push({
        productId: product._id,
        price: product.price,
        salePrice: salePrice || null,
        discountedPrice: validPrice,
      });
    }

    if (config.DebugMode) console.log(`[DEBUG] Subtotal calculated: ${subtotal.toFixed(2)}`);

    if (!items.length) {
      if (config.DebugMode) console.error('[DEBUG] No valid items found in the cart.');
      return res.status(400).send('No valid items in the cart');
    }

    // Apply discount
    let discountAmount = 0;
    let discountPercentage = 0;
    if (req.session.discountCode) {
      const discountCode = await DiscountCodeModel.findOne({
        name: {
          $regex: new RegExp(`^${req.session.discountCode}$`, 'i'),
        },
      });

      if (discountCode) {
        discountPercentage = discountCode.discountPercentage;
        discountAmount = subtotal * (discountPercentage / 100);
        if (config.DebugMode) console.log(`[DEBUG] Discount applied: ${discountPercentage}% => Amount: ${discountAmount.toFixed(2)}`);
      } else {
        if (config.DebugMode) console.warn('[DEBUG] Invalid discount code provided.');
      }
    }

    // Calculate discounted subtotal
    const discountedSubtotal = parseFloat((subtotal - discountAmount).toFixed(2));

    // Calculate sales tax with proper rounding
    let salesTaxAmount = 0;
    if (globalSettings.salesTax) {
      salesTaxAmount = parseFloat((discountedSubtotal * (globalSettings.salesTax / 100)).toFixed(2));
    }

    // Final total price
    const totalPrice = parseFloat((discountedSubtotal + salesTaxAmount).toFixed(2));

    if (config.DebugMode) console.log('[DEBUG] Final amounts calculated:');
    if (config.DebugMode)
      console.log({
        subtotal: subtotal.toFixed(2),
        discountAmount: discountAmount.toFixed(2),
        discountedSubtotal: discountedSubtotal.toFixed(2),
        salesTaxAmount: salesTaxAmount.toFixed(2),
        totalPrice: totalPrice.toFixed(2),
      });

    // Ensure PayPal `item_total` matches updated items
    const adjustedItemTotal = parseFloat(items.reduce((sum, item) => sum + parseFloat(item.unit_amount.value), 0).toFixed(2));

    if (config.DebugMode) console.log(`[DEBUG] Adjusted item total calculated: ${adjustedItemTotal.toFixed(2)}`);

    // Validate item_total and subtotal alignment
    if (adjustedItemTotal.toFixed(2) !== discountedSubtotal.toFixed(2)) {
      if (config.DebugMode) console.error(`[ERROR] Item total (${adjustedItemTotal.toFixed(2)}) does not match discounted subtotal (${discountedSubtotal.toFixed(2)}).`);
    }

    // Save the cart snapshot to MongoDB
    const cartSnapshot = await CartSnapshot.create({
      userId: user._id,
      items: cartSnapshotItems,
      total: totalPrice,
    });

    // Create PayPal order
    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer('return=representation');
    request.requestBody({
      intent: 'CAPTURE',
      purchase_units: [
        {
          amount: {
            currency_code: globalSettings.paymentCurrency,
            value: totalPrice.toFixed(2),
            breakdown: {
              item_total: {
                currency_code: globalSettings.paymentCurrency,
                value: adjustedItemTotal.toFixed(2),
              },
              discount: {
                currency_code: globalSettings.paymentCurrency,
                value: discountAmount.toFixed(2),
              },
              tax_total: {
                currency_code: globalSettings.paymentCurrency,
                value: salesTaxAmount.toFixed(2),
              },
            },
          },
          description: `${globalSettings.storeName} Cart Checkout | Account ID: ${req.user.id} | Terms of Service: ${config.baseURL}/tos`,
          items: items,
        },
      ],
      application_context: {
        brand_name: globalSettings.storeName,
        landing_page: 'NO_PREFERENCE',
        user_action: 'PAY_NOW',
        return_url: `${config.baseURL}/checkout/paypal/capture?snapshot_id=${cartSnapshot._id.toString()}`,
        cancel_url: `${config.baseURL}/cart`,
      },
    });

    // Execute PayPal order request
    const order = await paypalClientInstance.execute(request);

    // Debug final values sent to PayPal
    if (config.DebugMode) console.log('[DEBUG] Final PayPal request:', {
      items,
      adjustedItemTotal: adjustedItemTotal.toFixed(2),
      totalPrice: totalPrice.toFixed(2),
      salesTaxAmount: salesTaxAmount.toFixed(2),
      discountAmount: discountAmount.toFixed(2),
    });

    res.redirect(order.result.links.find((link) => link.rel === 'approve').href);
  } catch (error) {
    console.error(`[ERROR] Failed to create PayPal order: ${error.message}`);
    console.error(`Stack Trace: ${error.stack}`);
    next(error);
  }
});




app.get('/checkout/paypal/capture', checkAuthenticated, async (req, res, next) => {
  try {
      const { token, snapshot_id } = req.query;
      const request = new paypal.orders.OrdersCaptureRequest(token);
      request.requestBody({});

      const capture = await paypalClientInstance.execute(request);

      if (capture.result.status === 'COMPLETED') {
          // Fetch the cart snapshot using the snapshot_id
          const cartSnapshot = await CartSnapshot.findById(snapshot_id);
          if (!cartSnapshot) {
              throw new Error('Cart snapshot not found. Payment cannot be processed.');
          }

          const user = await userModel.findOne({ _id: cartSnapshot.userId });

          // Use the snapshot to fetch product details
          const products = await Promise.all(cartSnapshot.items.map(async (snapshotItem) => {
              const product = await productModel.findById(snapshotItem.productId);
              if (!product) {
                  throw new Error(`Product with ID ${snapshotItem.productId} not found.`);
              }
              return {
                  id: product._id,
                  name: product.name,
                  price: snapshotItem.discountedPrice,
                  discordRoleIds: product.discordRoleIds,
              };
          }));

          const transactionId = capture.result.id; // Get the transaction ID from PayPal response

          // Fetch discount code from the session if available
          const discountCode = req.session.discountCode || null;
          let discountPercentage = 0;

          if (discountCode) {
              const code = await DiscountCodeModel.findOne({ 
                name: { 
                  $regex: new RegExp(`^${discountCode}$`, 'i') 
                } 
              });

              if (code) {
                  discountPercentage = code.discountPercentage;

                  code.uses += 1;
                  await code.save();
              }
          }

      // Debug calculations
      const roundToTwo = (num) => Math.round(num * 100) / 100;

      // Calculate the original subtotal
      const originalSubtotal = roundToTwo(
        products.reduce((sum, product) => sum + product.price, 0)
      );
      if(config.DebugMode) console.log(`[DEBUG] Original Subtotal: ${originalSubtotal}`);

      // Calculate the discount amount
      const discountAmount = roundToTwo(originalSubtotal * (discountPercentage / 100));
      if(config.DebugMode) console.log(`[DEBUG] Discount Amount: ${discountAmount}`);

      // Calculate the discounted subtotal
      const discountedSubtotal = roundToTwo(originalSubtotal - discountAmount);
      if(config.DebugMode) console.log(`[DEBUG] Discounted Subtotal: ${discountedSubtotal}`);

      // Calculate sales tax
      let salesTaxAmount = 0;
      if (globalSettings.salesTax) {
        salesTaxAmount = roundToTwo(discountedSubtotal * (globalSettings.salesTax / 100));
        if(config.DebugMode) console.log(`[DEBUG] Sales Tax Amount: ${salesTaxAmount}`);
      }

      // Calculate the final total paid amount
      const totalPaid = roundToTwo(discountedSubtotal + salesTaxAmount);
      if(config.DebugMode) console.log(`[DEBUG] Total Paid: ${totalPaid}`);

// Validate structure before accessing
if (
  !capture.result ||
  !capture.result.purchase_units ||
  !capture.result.purchase_units[0] ||
  !capture.result.purchase_units[0].payments ||
  !capture.result.purchase_units[0].payments.captures ||
  !capture.result.purchase_units[0].payments.captures[0] ||
  !capture.result.purchase_units[0].payments.captures[0].amount ||
  !capture.result.purchase_units[0].payments.captures[0].amount.value
) {
  if(config.DebugMode) console.error('[DEBUG] Invalid capture structure:', JSON.stringify(capture, null, 2));
  throw new Error('Invalid response structure from PayPal capture.');
}

// Access the captured amount correctly
const paypalCapturedAmount = parseFloat(capture.result.purchase_units[0].payments.captures[0].amount.value);

if(config.DebugMode) console.log(`[DEBUG] PayPal Captured Amount: ${paypalCapturedAmount}`);

          // Get the current count of documents in the Payment collection to determine the next ID
          const paymentCount = await paymentModel.countDocuments({});
          const nextPaymentId = paymentCount + 1;

          const payment = new paymentModel({
            ID: nextPaymentId,
            transactionID: transactionId,
            paymentMethod: "paypal",
            userID: req.user.id,
            username: req.user.username,
            email: user.email,
            products: products.map(p => ({
                name: p.name,
                price: p.price, // Discounted price
                salePrice: cartSnapshot.items.find(i => i.productId.toString() === p.id.toString())?.salePrice || null,
                originalPrice: cartSnapshot.items.find(i => i.productId.toString() === p.id.toString())?.price,
            })),
            discountCode,
            discountPercentage,
            salesTax: globalSettings.salesTax,
            originalSubtotal: parseFloat(originalSubtotal.toFixed(2)),
            salesTaxAmount: parseFloat(salesTaxAmount.toFixed(2)),
            discountAmount: parseFloat(discountAmount.toFixed(2)),
            totalPaid: parseFloat(totalPaid.toFixed(2)),
        });
          await payment.save();

          // Filter out products that the user already owns
          const newProducts = products.filter(p => !user.ownedProducts.includes(p.id));

          // Update each product's statistics
          for (const product of products) {
            const productDoc = await productModel.findById(product.id);
            if (productDoc) {
                // Update product statistics
                productDoc.totalPurchases += 1;
                productDoc.totalEarned += product.price * (1 - discountPercentage / 100);
        
                // Handle serial products
                if (productDoc.productType === 'serials') {
                    // Verify serial availability
                    if (productDoc.serials || productDoc.serials.length !== 0) {
        
                    // Get a random serial key
                    const randomIndex = Math.floor(Math.random() * productDoc.serials.length);
                    const serialKey = productDoc.serials[randomIndex];
        
                    // Remove the used serial from the product
                    productDoc.serials.splice(randomIndex, 1);
        
                    // Initialize ownedSerials array if it doesn't exist
                    user.ownedSerials = user.ownedSerials || [];
        
                    // Add serial to user's owned serials
                    user.ownedSerials.push({
                        productId: productDoc._id,
                        productName: productDoc.name,
                        key: serialKey.key,
                        purchaseDate: new Date()
                    });
                  }
                }
        
                await productDoc.save();
            }
        }

          // Automatically give discord roles for each product
          const guild = await client.guilds.fetch(config.GuildID);

          if (guild) {
              try {
                  const guildMember = await guild.members.fetch(req.user.id);
          
                  if (guildMember) {
                      for (const product of products) {
                          // Check if discordRoleIds exists and is not empty
                          if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                              for (const roleId of product.discordRoleIds) {
                                  // Validate the role ID and ensure the role exists in the guild
                                  const role = guild.roles.cache.get(roleId);
                                  if (role) {
                                      // Add the role to the guild member
                                      await guildMember.roles.add(role);
                                  } else {
                                      if(config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                                  }
                              }
                          }
                      }
                  } else {
                      if(config.DebugMode) console.warn(`Guild member with ID ${req.user.id} could not be found.`);
                  }
              } catch (error) {
                  if(config.DebugMode) console.error(`Failed to fetch the guild member or add roles: ${error.message}`);
              }
          } else {
              if(config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
          }

          // Add the new purchased products to the user's ownedProducts array
          user.ownedProducts.push(...newProducts.map(p => p.id));

          // Update the user's totalSpent field
          user.totalSpent = (user.totalSpent || 0) + parseFloat(totalPaid.toFixed(2));

          // Clear the user's cart
          user.cart = [];
          await user.save();

          // Clear the discount code from the session after use
          delete req.session.discountCode;

          // Get the current date information
          const now = new Date();
          const currentYear = now.getFullYear();
          const currentMonthIndex = now.getMonth();

          // Update the statistics
          const stats = await statisticsModel.getStatistics();
          stats.totalEarned += parseFloat(totalPaid.toFixed(2));
          stats.totalPurchases += 1;
          stats.lastUpdated = Date.now();

          // Find or create the current year statistics
          let yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
          if (!yearlyStats) {
              yearlyStats = {
                  year: currentYear,
                  months: Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }))
              };
              stats.yearlyStats.push(yearlyStats);
          }

          // Ensure that the months array is correctly initialized
          if (!yearlyStats.months || yearlyStats.months.length !== 12) {
              yearlyStats.months = Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }));
          }

          // Update the monthly statistics for the current month
          yearlyStats.months[currentMonthIndex].totalEarned += parseFloat(totalPaid.toFixed(2));
          yearlyStats.months[currentMonthIndex].totalPurchases += 1;

          await stats.save();

      // Email invoice
      const emailContent = await utils.generateEmailContent({
        paymentMethod: 'PayPal',
        transactionId,
        userId: req.user.id,
        username: req.user.username,
        userEmail: user.email,
        products,
        totalPaid,
        discountCode,
        discountPercentage,
        salesTax: globalSettings.salesTax,
        salesTaxAmount,
        nextPaymentId,
        globalSettings,
        config,
      });

      if (config.EmailSettings.Enabled) {
        await utils.sendEmail(user.email, `Your Payment Invoice (#${nextPaymentId})`, emailContent);
      }

          // Send a log to Discord
          const productNames = products.map(product => product.name).join(', ');
          utils.sendDiscordLog('Purchase Completed', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has purchased \`${productNames}\` with \`PayPal\`.`);

          res.redirect(`/checkout/success?transactionId=${transactionId}`);
      } else {
          res.redirect('/cart');
      }
  } catch (error) {
      console.error('\x1b[31m%s\x1b[0m', `[ERROR] Failed to capture PayPal order: ${error.message}`);
      console.error('\x1b[33m%s\x1b[0m', `Stack Trace: ${error.stack}`);
      
      if (error.message.includes('invalid_client')) {
          next(new Error('There was an issue with the PayPal API credentials. Please check your configuration.'));
      } else {
          next(error);
      }
  }
});


app.post('/checkout/stripe', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const user = await userModel.findOne({ discordID: req.user.id }).populate('cart');
    if (!user || !user.cart.length) {
      return res.status(400).send('Cart is empty');
    }

    const currentDate = new Date();
    let subtotal = 0;
    const items = [];
    const cartSnapshotItems = [];
    let discountAmount = 0;
    let discountPercentage = 0;

    // Apply discount
    if (req.session.discountCode) {
      const discountCode = await DiscountCodeModel.findOne({
        name: { $regex: new RegExp(`^${req.session.discountCode}$`, 'i') },
      });

      if (discountCode) {
        discountPercentage = discountCode.discountPercentage;
      }
    }

    // Calculate subtotal and prepare Stripe items
    for (const cartItem of user.cart) {
      const product = await productModel.findById(cartItem._id);

      if (!product) continue;

      const isOnSale = product.onSale && product.saleStartDate <= currentDate && currentDate <= product.saleEndDate;
      const salePrice = isOnSale ? product.salePrice : null;
      const basePrice = isOnSale ? product.salePrice : product.price;

      subtotal += basePrice;

      const discountedPrice = basePrice * (1 - discountPercentage / 100);

      items.push({
        price_data: {
          currency: globalSettings.paymentCurrency,
          product_data: { name: product.name },
          unit_amount: Math.round(discountedPrice * 100), // Convert to cents
        },
        quantity: 1,
      });

      cartSnapshotItems.push({
        productId: product._id,
        price: product.price, // Original price
        salePrice, // Sale price if applicable, otherwise null
        discountedPrice: parseFloat(discountedPrice.toFixed(2)), // Final discounted price
      });
    }

    discountAmount = subtotal * (discountPercentage / 100);

    // Calculate discounted subtotal
    const discountedSubtotal = subtotal - discountAmount;

    // Calculate sales tax
    let salesTaxAmount = 0;
    if (globalSettings.salesTax) {
      salesTaxAmount = parseFloat((discountedSubtotal * (globalSettings.salesTax / 100)).toFixed(2));
    }

    // Final total amount
    const totalPrice = parseFloat((discountedSubtotal + salesTaxAmount).toFixed(2));

    // Debugging output
    if (config.DebugMode) {
      console.log('[DEBUG] Calculated amounts for Stripe checkout:');
      console.log({
        subtotal: subtotal.toFixed(2),
        discountAmount: discountAmount.toFixed(2),
        discountedSubtotal: discountedSubtotal.toFixed(2),
        salesTaxAmount: salesTaxAmount.toFixed(2),
        totalPrice: totalPrice.toFixed(2),
      });
    }

    // Save snapshot
    const cartSnapshot = await CartSnapshot.create({
      userId: user._id,
      items: cartSnapshotItems,
      total: totalPrice.toFixed(2),
    });

    // Add sales tax as a separate line item for Stripe
    if (salesTaxAmount > 0) {
      items.push({
        price_data: {
          currency: globalSettings.paymentCurrency,
          product_data: { name: 'Sales Tax' },
          unit_amount: Math.round(salesTaxAmount * 100), // Convert to cents
        },
        quantity: 1,
      });
    }

    // Create Stripe session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: items,
      mode: 'payment',
      success_url: `${config.baseURL}/checkout/stripe/capture?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${config.baseURL}/cart`,
      client_reference_id: cartSnapshot._id.toString(),
    });

    res.redirect(303, session.url);
  } catch (error) {
    console.error(`[ERROR] Failed to create Stripe session: ${error.message}`);
    next(error);
  }
});






app.get('/checkout/stripe/capture', checkAuthenticated, async (req, res, next) => {
  try {
      const { session_id } = req.query;

      const session = await stripe.checkout.sessions.retrieve(session_id);

      if (!session || session.payment_status !== 'paid') {
          return res.redirect('/cart');
      }

      // Fetch the cart snapshot using the client_reference_id
      const cartSnapshot = await CartSnapshot.findById(session.client_reference_id);
      if (!cartSnapshot) {
          throw new Error('Cart snapshot not found. Payment cannot be processed.');
      }

      const user = await userModel.findOne({ _id: cartSnapshot.userId });
      if (!user) {
          throw new Error('User not found for this cart snapshot.');
      }

      // Use the snapshot to fetch product details
      const products = await Promise.all(cartSnapshot.items.map(async (snapshotItem) => {
          const product = await productModel.findById(snapshotItem.productId);
          if (!product) {
              throw new Error(`Product with ID ${snapshotItem.productId} not found.`);
          }
          return {
              id: product._id,
              name: product.name,
              price: snapshotItem.discountedPrice,
              discordRoleIds: product.discordRoleIds,
          };
      }));

      const transactionId = session.payment_intent || session.id; // Use Stripe's payment intent ID as the transaction ID

      // Fetch discount code from the snapshot if available
      const discountCode = req.session.discountCode || null;
      let discountPercentage = 0;

      if (discountCode) {
          const code = await DiscountCodeModel.findOne({ 
              name: { 
                  $regex: new RegExp(`^${discountCode}$`, 'i') 
              }
          });

          if (code) {
              discountPercentage = code.discountPercentage;

              code.uses += 1;
              await code.save();
          }
      }

      // Filter out products that the user already owns
      const newProducts = products.filter(p => !user.ownedProducts.includes(p.id));

      // Update each product's statistics
      for (const product of products) {
        const productDoc = await productModel.findById(product.id);
        if (productDoc) {
            // Update product statistics
            productDoc.totalPurchases += 1;
            productDoc.totalEarned += product.price * (1 - discountPercentage / 100);
    
            // Handle serial products
            if (productDoc.productType === 'serials') {
                // Verify serial availability
                if (productDoc.serials || productDoc.serials.length !== 0) {
    
                // Get a random serial key
                const randomIndex = Math.floor(Math.random() * productDoc.serials.length);
                const serialKey = productDoc.serials[randomIndex];
    
                // Remove the used serial from the product
                productDoc.serials.splice(randomIndex, 1);
    
                // Initialize ownedSerials array if it doesn't exist
                user.ownedSerials = user.ownedSerials || [];
    
                // Add serial to user's owned serials
                user.ownedSerials.push({
                    productId: productDoc._id,
                    productName: productDoc.name,
                    key: serialKey.key,
                    purchaseDate: new Date()
                });
              }
            }
    
            await productDoc.save();
        }
    }

      // Automatically give Discord roles for each product
      const guild = await client.guilds.fetch(config.GuildID);

      if (guild) {
          try {
              const guildMember = await guild.members.fetch(req.user.id);

              if (guildMember) {
                  for (const product of products) {
                      // Check if discordRoleIds exists and is not empty
                      if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                          for (const roleId of product.discordRoleIds) {
                              // Validate the role ID and ensure the role exists in the guild
                              const role = guild.roles.cache.get(roleId);
                              if (role) {
                                  // Add the role to the guild member
                                  await guildMember.roles.add(role);
                              } else {
                                  if (config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                              }
                          }
                      }
                  }
              } else {
                  if (config.DebugMode) console.warn(`Guild member with ID ${req.user.id} could not be found.`);
              }
          } catch (error) {
              if (config.DebugMode) console.error(`Failed to fetch the guild member or add roles: ${error.message}`);
          }
      } else {
          if (config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
      }

// Calculate the original subtotal
const originalSubtotal = products.reduce((sum, product) => sum + product.price, 0);

// Calculate the discount amount
const discountAmount = discountPercentage
    ? parseFloat((originalSubtotal * (discountPercentage / 100)).toFixed(2))
    : 0;

// Decide where to apply tax
let taxableSubtotal = originalSubtotal

if (globalSettings.applyTaxAfterDiscount) {
    taxableSubtotal = originalSubtotal - discountAmount;
}

// Calculate sales tax
let salesTaxAmount = 0;
if (globalSettings.salesTax) {
    salesTaxAmount = parseFloat((taxableSubtotal * (globalSettings.salesTax / 100)).toFixed(2));
}

// Final total paid (including tax)
const totalPaid = parseFloat((taxableSubtotal + salesTaxAmount).toFixed(2));

// Debugging output
if(config.DebugMode) console.log({
    originalSubtotal: originalSubtotal.toFixed(2),
    discountAmount: discountAmount.toFixed(2),
    taxableSubtotal: taxableSubtotal.toFixed(2),
    salesTaxAmount: salesTaxAmount.toFixed(2),
    totalPaid: totalPaid.toFixed(2),
});

      // Get the current count of documents in the Payment collection to determine the next ID
      const paymentCount = await paymentModel.countDocuments({});
      const nextPaymentId = paymentCount + 1;

      const payment = new paymentModel({
        ID: nextPaymentId,
        transactionID: transactionId,
        paymentMethod: "stripe",
        userID: req.user.id,
        username: req.user.username,
        email: user.email,
        products: products.map(p => ({
          name: p.name,
          price: p.price, // Discounted price
          salePrice: cartSnapshot.items.find(i => i.productId.toString() === p.id.toString())?.salePrice || null,
          originalPrice: cartSnapshot.items.find(i => i.productId.toString() === p.id.toString())?.price,
      })),
        discountCode,
        discountPercentage,
        originalSubtotal: parseFloat(originalSubtotal.toFixed(2)),
        salesTaxAmount: parseFloat(salesTaxAmount.toFixed(2)),
        discountAmount: parseFloat(discountAmount.toFixed(2)),
        totalPaid: parseFloat(totalPaid.toFixed(2)),
    });
    await payment.save();


      // Add the new purchased products to the user's ownedProducts array
      user.ownedProducts.push(...newProducts.map(p => p.id));

      // Update the user's totalSpent field
      user.totalSpent = (user.totalSpent || 0) + parseFloat(totalPaid.toFixed(2));

      // Clear the user's cart
      user.cart = [];
      await user.save();

      // Clear the discount code from the session after use
      delete req.session.discountCode;

      // Get the current date information
      const now = new Date();
      const currentYear = now.getFullYear();
      const currentMonthIndex = now.getMonth();

      // Update the statistics
      const stats = await statisticsModel.getStatistics();
      stats.totalEarned += parseFloat(totalPaid.toFixed(2));
      stats.totalPurchases += 1;
      stats.lastUpdated = Date.now();

      // Find or create the current year statistics
      let yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
      if (!yearlyStats) {
          yearlyStats = {
              year: currentYear,
              months: Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }))
          };
          stats.yearlyStats.push(yearlyStats);
      }

      // Ensure that the months array is correctly initialized
      if (!yearlyStats.months || yearlyStats.months.length !== 12) {
          yearlyStats.months = Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }));
      }

      // Update the monthly statistics for the current month
      yearlyStats.months[currentMonthIndex].totalEarned += parseFloat(totalPaid.toFixed(2));
      yearlyStats.months[currentMonthIndex].totalPurchases += 1;

      await stats.save();

      // Email invoice
      const emailContent = await utils.generateEmailContent({
        paymentMethod: 'Stripe',
        transactionId,
        userId: req.user.id,
        username: req.user.username,
        userEmail: user.email,
        products,
        totalPaid,
        discountCode,
        discountPercentage,
        salesTax: globalSettings.salesTax,
        salesTaxAmount,
        nextPaymentId,
        globalSettings,
        config,
      });

      if (config.EmailSettings.Enabled) {
        await utils.sendEmail(user.email, `Your Payment Invoice (#${nextPaymentId})`, emailContent);
      }

      // Send a log to Discord
      const productNames = products.map(product => product.name).join(', ');
      utils.sendDiscordLog('Purchase Completed', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has purchased \`${productNames}\` with \`Stripe\`.`);

      res.redirect(`/checkout/success?transactionId=${transactionId}`);
  } catch (error) {
      console.error('\x1b[31m%s\x1b[0m', `[ERROR] Failed to capture Stripe order: ${error.message}`);
      console.error('\x1b[33m%s\x1b[0m', `Stack Trace: ${error.stack}`);
      res.status(500).send('An unexpected error occurred. Please try again later.');
  }
});

app.post('/checkout/coinbase', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const user = await userModel.findOne({ discordID: req.user.id }).populate('cart');
    if (!user || !user.cart.length) {
      return res.status(400).send('Cart is empty');
    }

    const currentDate = new Date();
    let subtotal = 0;
    const items = [];
    const cartSnapshotItems = [];
    let discountPercentage = 0;

    // Apply discount
    if (req.session.discountCode) {
      const discountCode = await DiscountCodeModel.findOne({
        name: {
          $regex: new RegExp(`^${req.session.discountCode}$`, 'i'),
        },
      });

      if (discountCode) {
        discountPercentage = discountCode.discountPercentage;
      }
    }

    // Calculate the subtotal and prepare items for Coinbase
    for (let i = 0; i < user.cart.length; i++) {
      const productId = user.cart[i]._id;
      const product = await productModel.findById(productId);

      if (!product) {
        user.cart.splice(i, 1);
        i--;
      } else {
        const isOnSale =
          product.onSale &&
          product.saleStartDate &&
          product.saleEndDate &&
          product.saleStartDate <= currentDate &&
          currentDate <= product.saleEndDate;

        const productPrice = isOnSale ? product.salePrice : product.price || 0;
        subtotal += productPrice;

        // Apply additional discount if applicable
        const discountedPrice = discountPercentage
          ? productPrice * (1 - discountPercentage / 100)
          : productPrice;

        items.push({
          name: product.name,
          amount: discountedPrice.toFixed(2),
          currency: globalSettings.paymentCurrency,
          quantity: 1,
        });

        cartSnapshotItems.push({
          productId: product._id,
          price: product.price,
          salePrice: isOnSale ? product.salePrice : null,
          discountedPrice: parseFloat(discountedPrice.toFixed(2)),
        });
      }
    }

    if (user.cart.length !== items.length) {
      await user.save();
    }

    // Calculate sales tax based on the discounted subtotal
    let salesTaxAmount = 0;
    if (globalSettings.salesTax) {
      salesTaxAmount = subtotal * (globalSettings.salesTax / 100);
      salesTaxAmount = Math.round(salesTaxAmount * 100) / 100;
    }

    // Add sales tax as a separate item
    if (salesTaxAmount > 0) {
      items.push({
        name: 'Sales Tax',
        amount: salesTaxAmount.toFixed(2),
        currency: globalSettings.paymentCurrency,
        quantity: 1,
      });
    }

    // Calculate the total amount
    const totalAmount = items.reduce((total, item) => total + parseFloat(item.amount) * item.quantity, 0);
    const roundedTotalAmount = Math.round(totalAmount * 100) / 100;

    // Save the cart snapshot to MongoDB
    const cartSnapshot = await CartSnapshot.create({
      userId: user._id,
      items: cartSnapshotItems,
      total: roundedTotalAmount,
    });

    // Prepare the charge data for Coinbase
    const chargeData = {
      name: globalSettings.storeName,
      description: 'Purchase from ' + globalSettings.storeName,
      pricing_type: 'fixed_price',
      local_price: {
        amount: roundedTotalAmount.toFixed(2),
        currency: globalSettings.paymentCurrency,
      },
      metadata: {
        userId: req.user.id,
        snapshotId: cartSnapshot._id.toString(),
        discountPercentage: discountPercentage,
        salesTax: globalSettings.salesTax ? `${globalSettings.salesTax}%` : '0%',
      },
    };

    const charge = await Charge.create(chargeData);

    res.redirect(303, charge.hosted_url);
  } catch (error) {
    console.error('\x1b[31m%s\x1b[0m', `[ERROR] Failed to create Coinbase charge: ${error.message}`);
    console.error('\x1b[33m%s\x1b[0m', `Stack Trace: ${error.stack}`);
    next(error);
  }
});



app.post('/webhooks/coinbase', express.raw({ type: 'application/json' }), async (req, res) => {
  const webhookSecret = config.Payments.Coinbase.WebhookSecret;
  const signature = req.headers['x-cc-webhook-signature'];

  try {
      // Store the raw body
      const rawBody = req.body;

      // Use Coinbase's built-in signature verification
      try {
          Webhook.verifySigHeader(rawBody, signature, webhookSecret);
          if (config.DebugMode) console.log('Successfully verified');
      } catch (error) {
          if (config.DebugMode) console.error('Failed to verify signature:', error.message);
          return res.status(400).send('Invalid signature');
      }

      // Parse the raw body to JSON
      const event = JSON.parse(rawBody.toString()).event;

      if (config.DebugMode) console.log('Parsed event:', event);

      if (event.type === 'charge:confirmed') {
          const charge = event.data;
          const snapshotId = charge.metadata.snapshotId;

          // Fetch the cart snapshot
          const cartSnapshot = await CartSnapshot.findById(snapshotId);
          if (!cartSnapshot) {
              throw new Error('Cart snapshot not found. Payment cannot be processed.');
          }

          const user = await userModel.findOne({ _id: cartSnapshot.userId });
          const discordUser = await client.users.fetch(user.discordID);

          if (!user) {
              return res.status(404).send('User not found');
          }

          // Use the snapshot to fetch product details
          const products = await Promise.all(cartSnapshot.items.map(async (snapshotItem) => {
              const product = await productModel.findById(snapshotItem.productId);
              if (!product) {
                  throw new Error(`Product with ID ${snapshotItem.productId} not found.`);
              }
              return {
                  id: product._id,
                  name: product.name,
                  price: snapshotItem.discountedPrice,
                  discordRoleIds: product.discordRoleIds,
              };
          }));

          const transactionId = charge.id; // Use Coinbase's charge ID as the transaction ID

          // Fetch discount code from the metadata if available
          let discountPercentage = 0;
          const discountCode = charge.metadata.discountCode || null;

          if (discountCode) {
              const code = await DiscountCodeModel.findOne({ 
                  name: { 
                      $regex: new RegExp(`^${discountCode}$`, 'i') 
                  }
              });

              if (code) {
                  discountPercentage = code.discountPercentage;

                  // Increment the usage count for the discount code
                  code.uses += 1;
                  await code.save();
              }
          }

          // Debug calculations
          const roundToTwo = (num) => Math.round(num * 100) / 100;

          // Calculate the original subtotal
          const originalSubtotal = roundToTwo(
              products.reduce((sum, product) => sum + product.price, 0)
          );
          if(config.DebugMode) console.log(`[DEBUG] Original Subtotal: ${originalSubtotal}`);

          // Calculate the discount amount
          const discountAmount = roundToTwo(originalSubtotal * (discountPercentage / 100));
          if(config.DebugMode) console.log(`[DEBUG] Discount Amount: ${discountAmount}`);

          // Calculate the discounted subtotal
          const discountedSubtotal = roundToTwo(originalSubtotal - discountAmount);
          if(config.DebugMode) console.log(`[DEBUG] Discounted Subtotal: ${discountedSubtotal}`);

          // Calculate sales tax
          let salesTaxAmount = 0;
          if (globalSettings.salesTax) {
              salesTaxAmount = roundToTwo(discountedSubtotal * (globalSettings.salesTax / 100));
              if(config.DebugMode) console.log(`[DEBUG] Sales Tax Amount: ${salesTaxAmount}`);
          }

          // Calculate the final total paid amount
          const totalPaid = roundToTwo(discountedSubtotal + salesTaxAmount);
          if(config.DebugMode) console.log(`[DEBUG] Total Paid: ${totalPaid}`);

          // Get the current count of documents in the Payment collection to determine the next ID
          const paymentCount = await paymentModel.countDocuments({});
          const nextPaymentId = paymentCount + 1;

          const payment = new paymentModel({
              ID: nextPaymentId,
              transactionID: transactionId,
              paymentMethod: "coinbase",
              userID: user._id,
              username: discordUser.username,
              email: user.email,
              products: products.map(p => ({
                name: p.name,
                price: p.price, // Discounted price
                salePrice: cartSnapshot.items.find(i => i.productId.toString() === p.id.toString())?.salePrice || null,
                originalPrice: cartSnapshot.items.find(i => i.productId.toString() === p.id.toString())?.price,
            })),
              discountCode,
              discountPercentage,
              salesTax: globalSettings.salesTax,
              originalSubtotal: parseFloat(originalSubtotal.toFixed(2)),
              salesTaxAmount: parseFloat(salesTaxAmount.toFixed(2)),
              discountAmount: parseFloat(discountAmount.toFixed(2)),
              totalPaid: parseFloat(totalPaid.toFixed(2)),
          });
          await payment.save();

          // Filter out products that the user already owns
          const newProducts = products.filter(p => !user.ownedProducts.includes(p.id));

          for (const product of products) {
            const productDoc = await productModel.findById(product.id);
            if (productDoc) {
                // Update product statistics
                productDoc.totalPurchases += 1;
                productDoc.totalEarned += parseFloat(totalPaid.toFixed(2));
        
                // Handle serial products
                if (productDoc.productType === 'serials') {
                    // Verify serial availability
                    if (productDoc.serials || productDoc.serials.length !== 0) {
        
                    // Get a random serial key
                    const randomIndex = Math.floor(Math.random() * productDoc.serials.length);
                    const serialKey = productDoc.serials[randomIndex];
        
                    // Remove the used serial from the product
                    productDoc.serials.splice(randomIndex, 1);
        
                    // Initialize ownedSerials array if it doesn't exist
                    user.ownedSerials = user.ownedSerials || [];
        
                    // Add serial to user's owned serials
                    user.ownedSerials.push({
                        productId: productDoc._id,
                        productName: productDoc.name,
                        key: serialKey.key,
                        purchaseDate: new Date()
                    });
                  }
                }
        
                await productDoc.save();
            }
        }

          // Automatically give Discord roles for each product
          const guild = await client.guilds.fetch(config.GuildID);

          if (guild) {
              try {
                  const guildMember = await guild.members.fetch(user.discordID);
                  if (guildMember) {
                      for (const product of products) {
                          if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                              for (const roleId of product.discordRoleIds) {
                                  const role = guild.roles.cache.get(roleId);
                                  if (role) {
                                      await guildMember.roles.add(role);
                                  } else {
                                      if (config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                                  }
                              }
                          }
                      }
                  } else {
                      if (config.DebugMode) console.warn(`Guild member with ID ${user.discordID} could not be found.`);
                  }
              } catch (error) {
                  if (config.DebugMode) console.error(`Failed to fetch the guild member or add roles: ${error.message}`);
              }
          } else {
              if (config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
          }

          // Add the new purchased products to the user's ownedProducts array
          user.ownedProducts.push(...newProducts.map(p => p.id));

          // Update the user's totalSpent field
          user.totalSpent = (user.totalSpent || 0) + parseFloat(totalPaid.toFixed(2));

          // Clear the user's cart
          user.cart = [];
          await user.save();

          // Update the statistics
          const stats = await statisticsModel.getStatistics();
          stats.totalEarned += parseFloat(totalPaid.toFixed(2));
          stats.totalPurchases += 1;
          stats.lastUpdated = Date.now();

          const now = new Date();
          const currentYear = now.getFullYear();
          const currentMonthIndex = now.getMonth();

          let yearlyStats = stats.yearlyStats.find(y => y.year === currentYear);
          if (!yearlyStats) {
              yearlyStats = {
                  year: currentYear,
                  months: Array(12).fill(null).map(() => ({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 }))
              };
              stats.yearlyStats.push(yearlyStats);
          }

          yearlyStats.months[currentMonthIndex].totalEarned += parseFloat(totalPaid.toFixed(2));
          yearlyStats.months[currentMonthIndex].totalPurchases += 1;

          await stats.save();

          const emailContent = await utils.generateEmailContent({
            paymentMethod: 'Coinbase',
            transactionId,
            userId: user._id,
            username: discordUser.username,
            userEmail: user.email,
            products,
            totalPaid,
            discountCode,
            discountPercentage,
            salesTax: globalSettings.salesTax,
            salesTaxAmount,
            nextPaymentId,
            globalSettings,
            config,
          });
          
          // Send the email invoice
          if (config.EmailSettings.Enabled) {
            await utils.sendEmail(user.email, `Your Payment Invoice (#${nextPaymentId})`, emailContent);
          }

            // Send a log to Discord
            const productNames = products.map(product => product.name).join(', ');
            utils.sendDiscordLog('Purchase Completed', `[${discordUser.username}](${config.baseURL}/profile/${user.discordID}) has purchased \`${productNames}\` with \`Coinbase\`.`);

            res.status(200).send('Webhook processed');
        } else {
            res.status(400).send('Event type not supported');
        }
    } catch (error) {
        console.error(`[ERROR] Failed to process Coinbase webhook: ${error.message}`);
        res.status(500).send('Server error');
    }
});


app.get('/checkout/success', checkAuthenticated, async (req, res, next) => {
  try {
      const transactionId = req.query.transactionId;

      const payment = await paymentModel.findOne({ transactionID: transactionId });
      if (!payment) return res.redirect('/cart');

      if (payment.userID !== req.user.id) return res.redirect('/');

      // Calculate the original subtotal (before discount)
      let originalSubtotal = payment.products.reduce((sum, product) => sum + product.price, 0);

      // Calculate the sales tax on the original subtotal
      let salesTaxAmount = 0;
      if (globalSettings.salesTax) {
          salesTaxAmount = originalSubtotal * (globalSettings.salesTax / 100);
          // Ensure precision by rounding to 2 decimal places
          salesTaxAmount = parseFloat(salesTaxAmount.toFixed(2));
      }

      // Apply the discount if applicable
      let discountAmount = 0;
      if (payment.discountPercentage) {
          discountAmount = originalSubtotal * (payment.discountPercentage / 100);
          // To ensure precision, round to 2 decimal places
          discountAmount = parseFloat(discountAmount.toFixed(2));
      }

      res.render('payment-success', {
        user: req.user,
        cartProducts: payment.products,
        email: payment.email,
        totalPrice: payment.totalPaid,
        discountCode: payment.discountCode,
        discountPercentage: payment.discountPercentage,
        salesTaxAmount: payment.salesTaxAmount,
        transactionId: payment.transactionID,
        payment,
        existingUser: { username: payment.username },
        config
    });
  } catch (error) {
      console.error('Error rendering payment success page:', error);
      next(error);
  }
});







app.get('/profile/:userId', checkAuthenticated, async (req, res, next) => {
  try {
      const userId = req.params.userId;

      // Check if the logged-in user is either the owner of the profile or a staff member
      if (!req.isStaff() && (!req.user || req.user.id !== userId)) return res.redirect('/');

      // Find the user by their Discord ID
      const user = await userModel.findOne({ discordID: userId });
      if (!user) return res.redirect('/');
      const fullUser = await client.users.fetch(userId, { force: true });

      const [ownedProducts, allProducts] = await Promise.all([
        productModel.find({ _id: { $in: user.ownedProducts } }).lean(),
        productModel.find({}).lean()  // Get ALL products, not just unowned ones
    ]);

    // Filter and process serial products separately
    const serialProducts = allProducts
        .filter(p => p.productType === 'serials')
        .map(p => ({
            ...p,
            stockCount: (p.serials || []).length
        }));

    // Filter products for the regular product dropdown (excluding owned, serials, and free products)
    const products = allProducts.filter(p => 
      !user.ownedProducts.includes(p._id) && 
      p.productType !== "digitalFree" &&
      (p.productType !== "serials" || p.serialRequiresFile)
  );

    // Process Markdown for service products
    const renderedOwnedProducts = ownedProducts.map(product => {
      if (product.productType === 'service' && product.serviceMessage) {
        product.renderedServiceMessage = md.render(product.serviceMessage);
      } else {
        product.renderedServiceMessage = '';
      }
      return product;
    });


    res.render('profile', {
        userInfo: user,
        fullUser,
        ownedProducts: renderedOwnedProducts,
        existingUser: user,
        user: req.user,
        products: products,
        serialProducts: serialProducts,
        isStaff: req.isStaff()
    });
  } catch (error) {
      console.error('Error fetching user profile:', error);
      next(error);
  }
});


  app.post('/profile/:userId/delete/:productId', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
    try {
      const { userId, productId } = req.params;
  
      const user = await userModel.findOne({ discordID: userId });
      if (!user) return res.status(404).send('User not found');
  
      const discordUser = await client.users.fetch(userId);

      const product = await productModel.findById(productId);
      if (!product) return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });
  
      // Filter out null or undefined values and then remove the specified product
      user.ownedProducts = user.ownedProducts.filter(p => p && p.toString() !== productId);
      await user.save();
  
      const guild = await client.guilds.fetch(config.GuildID);
      if (guild) {
          try {
              const guildMember = await guild.members.fetch(userId);
      
              if (guildMember) {
                  // Check if the product has associated Discord roles to assign
                  if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                      for (const roleId of product.discordRoleIds) {
                          // Validate the role ID and ensure the role exists in the guild
                          const role = guild.roles.cache.get(roleId);
                          if (role) {
                              // Add the role to the guild member
                              await guildMember.roles.remove(role);
                          } else {
                              if(config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                          }
                      }
                  }
              } else {
                  if(config.DebugMode) console.warn(`Guild member with ID ${userId} could not be found.`);
              }
          } catch (error) {
              if(config.DebugMode) console.error(`Failed to fetch the guild member or remove roles: ${error.message}`);
          }
      } else {
          if(config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
      }

      utils.sendDiscordLog('Product Removed from User',`[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has removed the product \`${product.name}\` from [${discordUser.username}](${config.baseURL}/profile/${userId})'s owned products.`);
  
      res.redirect(`/profile/${userId}`);
    } catch (error) {
      console.error('Error deleting product from user:', error);
      next(error);
    }
  });

  app.post('/profile/:userId/add-product', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
    try {
        const { userId } = req.params;
        const { productId } = req.body;
  
        const user = await userModel.findOne({ discordID: userId });
        if (!user) return res.status(404).send('User not found');
  
        const discordUser = await client.users.fetch(userId);
  
        const product = await productModel.findById(productId);
        if (!product) return res.status(404).render('error', { errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' });
  
        // Check if the product already exists in the user's ownedProducts
        if (!user.ownedProducts.includes(productId)) {
            // Add the productId to the user's ownedProducts array
            user.ownedProducts.push(productId);
  
            // Automatically give discord roles based on the product's discordRoleIds
            const guild = await client.guilds.fetch(config.GuildID);
            if (guild) {
                try {
                    const guildMember = await guild.members.fetch(userId);
            
                    if (guildMember) {
                        // Check if the product has associated Discord roles to assign
                        if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                            for (const roleId of product.discordRoleIds) {
                                // Validate the role ID and ensure the role exists in the guild
                                const role = guild.roles.cache.get(roleId);
                                if (role) {
                                    // Add the role to the guild member
                                    await guildMember.roles.add(role);
                                } else {
                                    if(config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                                }
                            }
                        }
                    } else {
                        if(config.DebugMode) console.warn(`Guild member with ID ${userId} could not be found.`);
                    }
                } catch (error) {
                    if(config.DebugMode) console.error(`Failed to fetch the guild member or add roles: ${error.message}`);
                }
            } else {
                if(config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
            }
  
            // Save the updated user document
            await user.save();
            utils.sendDiscordLog('Product Added to User',`[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has added the product \`${product.name}\` to [${discordUser.username}](${config.baseURL}/profile/${userId})'s owned products.`);
        }
  
        res.redirect(`/profile/${userId}`);
    } catch (error) {
        console.error('Error adding product to user:', error);
        next(error);
    }
  });
  
  app.post('/profile/:userId/add-serial', checkAuthenticated, checkStaffAccess, csrfProtection, async (req, res, next) => {
    try {
        const { userId } = req.params;
        const { productId } = req.body;
  
        const user = await userModel.findOne({ discordID: userId });
        if (!user) return res.status(404).send('User not found');
  
        const discordUser = await client.users.fetch(userId);
  
        const product = await productModel.findById(productId);
        if (!product) return res.status(404).render('error', { 
            errorMessage: 'The requested product could not be found. Please check the URL or browse available products.' 
        });

        // Check if product has available serials
        if (!product.serials || product.serials.length === 0) {
            return res.status(400).render('error', { 
                errorMessage: 'This product has no available serial keys.' 
            });
        }

        // Get a random serial key
        const randomIndex = Math.floor(Math.random() * product.serials.length);
        const serialKey = product.serials[randomIndex];

        // Remove the used serial key from the product
        product.serials.splice(randomIndex, 1);
        await product.save();

        // Check if the product already exists in the user's ownedProducts, if not, push it to ownedProducts
        if (!user.ownedProducts.includes(productId)) user.ownedProducts.push(productId);

        // Add serial to user's owned serials
        user.ownedSerials = user.ownedSerials || [];
        user.ownedSerials.push({
            productId: product._id,
            productName: product.name,
            key: serialKey.key,
            purchaseDate: new Date()
        });

        // Automatically give discord roles based on the product's discordRoleIds
        const guild = await client.guilds.fetch(config.GuildID);
        if (guild) {
            try {
                const guildMember = await guild.members.fetch(userId);
        
                if (guildMember) {
                    // Check if the product has associated Discord roles to assign
                    if (product.discordRoleIds && product.discordRoleIds.length > 0) {
                        for (const roleId of product.discordRoleIds) {
                            // Validate the role ID and ensure the role exists in the guild
                            const role = guild.roles.cache.get(roleId);
                            if (role) {
                                // Add the role to the guild member
                                await guildMember.roles.add(role);
                            } else {
                                if(config.DebugMode) console.warn(`Role ID ${roleId} does not exist in the guild.`);
                            }
                        }
                    }
                } else {
                    if(config.DebugMode) console.warn(`Guild member with ID ${userId} could not be found.`);
                }
            } catch (error) {
                if(config.DebugMode) console.error(`Failed to fetch the guild member or add roles: ${error.message}`);
            }
        } else {
            if(config.DebugMode) console.error(`Guild with ID ${config.GuildID} could not be found.`);
        }

        await user.save();

        utils.sendDiscordLog(
            'Serial Key Added to User',
            `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has given a serial key for \`${product.name}\` to [${discordUser.username}](${config.baseURL}/profile/${userId}).`
        );

        res.redirect(`/profile/${userId}#serials`);
    } catch (error) {
        console.error('Error adding serial to user:', error);
        next(error);
    }
});

app.post('/profile/:userId/ban', checkAuthenticated, checkStaffAccess, async (req, res, next) => {
  try {
      const userId = req.params.userId;

      const user = await userModel.findOne({ discordID: userId });
      if (!user) return res.status(404).render('error', { errorMessage: 'User not found' });

      const discordUser = await client.users.fetch(userId);

      // Toggle the banned status
      user.banned = !user.banned;
      await user.save();

      utils.sendDiscordLog('User Banned',`[${req.user.username}](${config.baseURL}/profile/${req.user.id}) banned [${discordUser.username}](${config.baseURL}/profile/${userId})`);

      res.redirect(`/profile/${userId}`);
  } catch (error) {
      console.error('Error toggling ban status:', error);
      next(error);
  }
});


app.get('/reviews', async (req, res, next) => {
  try {
    const perPage = 9; // Number of reviews per page
    const page = parseInt(req.query.page) || 1;

    let products = [];
    let existingUser = null;

    if (req.user) {
      // Fetch user's owned products
      existingUser = await userModel.findOne({ discordID: req.user.id }).populate('ownedProducts');
      products = existingUser ? existingUser.ownedProducts : [];

      // Add free products (digitalFree) to the list of products the user can review
      const freeProducts = await productModel.find({ productType: 'digitalFree' });
      products = [...products, ...freeProducts];

      // Fetch all reviews by the logged-in user
      const userReviews = await reviewModel.find({ discordID: req.user.id });

      // Exclude products already reviewed
      const reviewedProductIds = userReviews.map(review => review.product.toString());
      products = products.filter(product => !reviewedProductIds.includes(product._id.toString()));
    }

    // Fetch total reviews count and paginate reviews
    const totalReviews = await reviewModel.countDocuments();
    const reviews = await reviewModel
      .find()
      .sort({ createdAt: -1 })
      .skip((page - 1) * perPage)
      .limit(perPage);

    // Fetch Discord user data for each review with caching
    const reviewsWithDiscordData = await Promise.all(reviews.map(async (review) => {
      const cachedDiscordUser = cache.get(`discordUser_${review.discordID}`);
      
      if (cachedDiscordUser) {
        return {
          ...review.toObject(),
          discordUsername: cachedDiscordUser.username,
          discordAvatar: cachedDiscordUser.avatar
        };
      }
      
      try {
        const discordUser = await client.users.fetch(review.discordID);
        const discordUserData = {
          username: discordUser.username,
          avatar: discordUser.displayAvatarURL({ dynamic: true })
        };
        
        // Cache the Discord user data
        cache.set(`discordUser_${review.discordID}`, discordUserData);
        
        return {
          ...review.toObject(),
          discordUsername: discordUserData.username,
          discordAvatar: discordUserData.avatar
        };
      } catch (error) {
        return {
          ...review.toObject(),
          discordUsername: review.discordUsername || 'Unknown User',
          discordAvatar: review.discordAvatarLocalPath || '/images/default-avatar.png'
        };
      }
    }));

    const totalPages = Math.ceil(totalReviews / perPage);

    const allReviews = await reviewModel.find();
    const totalReviews2 = reviews.length;
    const averageRating = totalReviews2 > 0 
      ? (allReviews.reduce((sum, review) => sum + review.rating, 0) / totalReviews).toFixed(1)
      : 0;

      res.render('reviews', {
        user: req.user,
        reviews: reviewsWithDiscordData,
        products,
        existingUser,
        currentPage: page,
        totalPages,
        stats: {
          averageRating,
          totalReviews
        }
      });
  } catch (error) {
    console.error('Error fetching reviews:', error);
    next(error);
  }
});




app.post('/reviews', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const { productId, rating, comment } = req.body;

    const product = await productModel.findById(productId);
    if (!product) return res.status(404).send('Product not found.');

    // Check if the user has already reviewed the product
    const existingReview = await reviewModel.findOne({ discordID: req.user.id, product: productId });
    if (existingReview) return res.redirect('/reviews');

    const settings = await settingsModel.findOne();

    let canReview = false;

    if (product.productType === 'digitalFree') {
      // Allow reviewing free products without ownership
      canReview = true;
    } else {
      // Check if the user owns the product
      const existingUser = await userModel.findOne({ discordID: req.user.id });
      const validOwnedProducts = await productModel.find({ _id: { $in: existingUser.ownedProducts.filter(id => id) }}).select('_id');
      const ownsProduct = validOwnedProducts.some(validProduct => validProduct._id.toString() === product._id.toString());
      if (ownsProduct) canReview = true;
    }

    if (!canReview) return res.status(400).send('You can only review products you own or free products.');

    // Fetch Discord avatar and username
    const discordUser = await client.users.fetch(req.user.id);
    const discordAvatarUrl = discordUser.displayAvatarURL({ format: 'png', size: 256 });
    const discordUsername = discordUser.username;

    // Save avatar locally
    const avatarFileName = `avatar-${req.user.id}-${Date.now()}.png`;
    const avatarLocalPath = path.join(__dirname, 'uploads/reviews', avatarFileName);

    const response = await axios.get(discordAvatarUrl, { responseType: 'stream' });
    response.data.pipe(fs.createWriteStream(avatarLocalPath));

    // Wait for the file to be fully saved
    await new Promise(resolve => response.data.on('end', resolve));

    // Create a new review
    const newReview = new reviewModel({
      discordID: req.user.id,
      discordUsername,
      discordAvatarLocalPath: `/uploads/reviews/${avatarFileName}`,
      productName: product.name,
      product: productId,
      rating,
      comment
    });

    await newReview.save();

    const reviewChannel = await client.channels.fetch(settings.discordReviewChannel);
    if (reviewChannel && settings.sendReviewsToDiscord) {
      const reviewEmbed = new Discord.EmbedBuilder()
        .setAuthor({ name: `${discordUsername}`, iconURL: discordAvatarUrl })
        .setTitle(`${product.name}`)
        .setURL(`${config.baseURL}/products/${product.urlId}`)
        .setColor(settings.accentColor)
        .setDescription(`${comment}\n\n${'⭐'.repeat(rating)}`)

      await reviewChannel.send({ embeds: [reviewEmbed] });
    }

    utils.sendDiscordLog('New Review', `[${req.user.username}](${config.baseURL}/profile/${req.user.id}) has reviewed \`${product.name}\``);

    res.redirect('/reviews');
  } catch (error) {
    console.error('Error creating review:', error);
    next(error);
  }
});

app.post('/reviews/:id/delete', checkAuthenticated, csrfProtection, async (req, res, next) => {
  try {
    const reviewId = req.params.id;
    const review = await reviewModel.findById(reviewId);

    if (!review) return res.redirect('/reviews');

    const settings = await settingsModel.findOne();

    // Staff can always delete reviews
    if (req.isStaff()) {
      await reviewModel.findByIdAndDelete(reviewId);
      return res.redirect('/reviews');
    }

    // If allowReviewDeletion is true, allow the user to delete their own review
    if (settings.allowReviewDeletion && req.user.id === review.discordID) {
      await reviewModel.findByIdAndDelete(reviewId);
      return res.redirect('/reviews');
    }

    // If not staff and not authorized, deny access
    return res.status(403).send('You are not authorized to delete this review');
  } catch (error) {
    console.error('Error deleting review:', error);
    next(error);
  }
});

app.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      console.error('Error during logout:', err);
      return next(err);
    }
    res.redirect('/');
  });
});

// Handle redirects from config.yml
if (config.Redirects && Array.isArray(config.Redirects)) {
  config.Redirects.forEach((redirect) => {
    const { path, target, method = "GET", statusCode = 301 } = redirect;

    // Check for placeholders like :wildcard in the target
    app[method.toLowerCase()](path, (req, res) => {
      const wildcard = req.params[0] || "";
      const redirectUrl = target.replace(":wildcard", wildcard);

      if(config.DebugMode) console.log(`Redirecting ${req.originalUrl} to ${redirectUrl}`);
      res.redirect(statusCode, redirectUrl);
    });
  });
}


app.get('/error', (req, res) => {
  const errorMessage = "This is a test error message to verify the error page design.";
  res.status(500).render('error', {
      errorMessage,
  });
});

app.use((req, res, next) => {
  res.status(404).render('error', {
      errorMessage: 'Page not found. The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.'
  });
});

// General error handler for other server errors
app.use(async(err, req, res, next) => {
  console.error(err.stack);

  const products = await productModel.find().sort({ position: 1 });

  const errorPrefix = `[${new Date().toLocaleString()}] [v${packageFile.version}]`;
  const errorMsg = `\n\n${errorPrefix}\n${err.stack}\n\nProducts:\n${products}`;
  fs.appendFile("./logs.txt", errorMsg, (e) => {
    if (e) console.log(e);
  });

  res.status(500).render('error', { errorMessage: 'Something went wrong on our end. Please try again later.' });
});

// Start the server
app.listen(config.Port, async () => {

  console.log("――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――");
  console.log("                                                                          ");
  if (config.LicenseKey) console.log(`${color.green.bold.underline(`Plex Store v${packageFile.version} is now Online!`)} (${color.gray(`${config.LicenseKey.slice(0, -10)}`)})`);
  if (!config.LicenseKey) console.log(`${color.green.bold.underline(`Plex Store v${packageFile.version} is now Online! `)}`);
  console.log(`• Join our discord server for support, ${color.cyan(`discord.gg/plexdev`)}`);
  console.log(`• Documentation can be found here, ${color.cyan(`docs.plexdevelopment.net`)}`);
  console.log(`• By using this product you agree to all terms located here, ${color.yellow(`plexdevelopment.net/tos`)}`);
  if (config.LicenseKey) console.log("                                                                          ");
  if (config.LicenseKey) console.log(`${color.green.bold.underline(`Source Code:`)}`);
  if (config.LicenseKey) console.log(`• You can buy the full source code at ${color.yellow(`plexdevelopment.net/products/pstoresourcecode`)}`);
  if (config.LicenseKey) console.log(`• Use code ${color.green.bold.underline(`PLEX`)} for 10% OFF!`);
  console.log("                                                                          ");
  console.log("――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――");
  console.log(color.yellow("[DASHBOARD] ") + `Web Server has started and is accessible with port ${color.yellow(`${config.Port}`)}`)
});
