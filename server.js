require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const crypto = require('crypto');
const session = require("express-session");
const passport = require("passport");
const GitHubStrategy = require("passport-github2").Strategy;
const cors = require("cors");
const { Octokit } = require("@octokit/rest");
const cookieParser = require('cookie-parser');
const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB Connection URI
const MONGO_URI = process.env.MONGO_URI;

// Add before other middleware
app.use(cookieParser());

// Connect to MongoDB with error handling
mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    dbName: "cloudpatch" 
  })
  .then(() => console.log("MongoDB connected to cloudpatch database"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// User model with timestamps
const userSchema = new mongoose.Schema({
  githubId: {
    type: String,
    required: true,
    unique: true
  },
  username: {
    type: String,
    required: true
  },
  githubToken: String,
  avatar: String,
  email: String,
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model("User", userSchema);

// GitHub auth configuration
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
// Update the callback URL to use the deployed URL
const GITHUB_CALLBACK_URL = process.env.NODE_ENV === "production" 
  ? "https://cloudpatch-backend-js.onrender.com/auth/github/callback"
  : "http://localhost:5000/auth/github/callback";

// Passport config
passport.use(
  new GitHubStrategy(
    {
      clientID: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
      callbackURL: GITHUB_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ githubId: profile.id });
        
        if (user) {
          // Update token and last login
          user.githubToken = accessToken;
          user.lastLogin = new Date();
          await user.save();
          return done(null, user);
        }

        // Create new user with token
        user = await new User({
          githubId: profile.id,
          username: profile.username,
          githubToken: accessToken,
          avatar: profile.photos?.[0]?.value,
          email: profile._json.email
        }).save();

        done(null, user);
      } catch (err) {
        console.error("Error in GitHub strategy:", err);
        done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Update CORS configuration for production
const FRONTEND_URL = process.env.NODE_ENV === "production" 
  ? ["https://cloudpatch-frontend.onrender.com", "electron://app"]
  : ['http://localhost:3000', 'http://localhost:8000', 'electron://app'];

// Middleware
// Middleware
// CORS configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:8000',
  'https://cloudpatch-frontend.onrender.com',
  'electron://app'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Log incoming requests for debugging
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  console.log('Request origin:', origin);
  console.log('Request headers:', req.headers);
  
  // Set CORS headers for preflight requests
  // Needed for browser support
  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, User-Agent, Origin, X-Requested-With');
    res.header('Access-Control-Max-Age', '86400'); // 24 hours
    res.header('Access-Control-Allow-Credentials', 'true');
    
    // Check and set allowed origin
    if (origin && (allowedOrigins.includes(origin) || origin.includes('localhost'))) {
      res.header('Access-Control-Allow-Origin', origin);
    }
    
    return res.status(204).end();
  }
  
  // For non-OPTIONS requests
  if (origin && (allowedOrigins.includes(origin) || origin.includes('localhost'))) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, User-Agent, Origin, X-Requested-With');
    res.header('Access-Control-Expose-Headers', 'Authorization, Content-Disposition');
  }
  
  next();
});

// Then use cors middleware with the same settings
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if(!origin) return callback(null, true);
    
    if(allowedOrigins.indexOf(origin) !== -1 || origin.includes('localhost')) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'User-Agent', 'Origin', 'X-Requested-With'],
  exposedHeaders: ['Authorization', 'Content-Disposition']
}));

// Add debug logging for all requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  console.log('Request headers:', req.headers);
  next();
});

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: process.env.NODE_ENV === "production" ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Auth middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: "Not authenticated" });
};

// Status endpoint
app.get("/api/status", (req, res) => {
  res.json({ status: "online" });
});

// Network check endpoint
app.get("/api/network-test", async (req, res) => {
  try {
    const results = {
      github: false,
      internet: false
    };
    
    // Test GitHub API connectivity
    try {
      const githubResponse = await fetch("https://api.github.com", {
        timeout: 5000,
        headers: { "User-Agent": "Network Test" }
      });
      results.github = githubResponse.ok;
    } catch (error) {
      console.error("GitHub connectivity test failed:", error.message);
    }
    
    // Test general internet connectivity
    try {
      const internetResponse = await fetch("https://www.google.com", {
        timeout: 5000,
        headers: { "User-Agent": "Network Test" }
      });
      results.internet = internetResponse.ok;
    } catch (error) {
      console.error("Internet connectivity test failed:", error.message);
    }
    
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// On your backend server
app.post('/create-github-issue', async (req, res) => {
  try {
    const { title, body, returnUrl } = req.body;
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    // Store the issue data in a temporary session or database
    // Use a unique ID to reference it instead of passing all data in URL
    const sessionId = generateUniqueId();
    await storeTemporaryIssueData(sessionId, { token, title, body, returnUrl });
    
    // Return a redirect URL with just the session ID
    res.json({
      redirect_url: `${process.env.BASE_URL}/github-issue-creator-secure?session=${sessionId}`
    });
  } catch (error) {
    console.error('Error creating issue:', error);
    res.status(500).json({ error: 'Failed to prepare issue creation' });
  }
});

// Then create a new endpoint that handles the actual GitHub issue creation
app.get('/github-issue-creator-secure', async (req, res) => {
  try {
    const { session } = req.query;
    if (!session) {
      return res.status(400).send('Missing session ID');
    }
    
    // Retrieve the stored issue data using the session ID
    const issueData = await getTemporaryIssueData(session);
    if (!issueData) {
      return res.status(404).send('Session not found or expired');
    }
    
    // Now use this data to render a page that will help create a GitHub issue
    // This avoids exposing sensitive data in URLs
    
    // Render an HTML page that will handle GitHub repo selection and issue creation
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Create GitHub Issue</title>
        <style>
          /* Add your CSS here */
        </style>
      </head>
      <body>
        <h1>Create GitHub Issue</h1>
        <div id="repo-selector">
          <!-- JavaScript will populate this -->
        </div>
        
        <script>
          // Use session ID to fetch data securely from backend
          const sessionId = "${session}";
          
          // Initialize page with the session data
          async function init() {
            try {
              // JavaScript that handles repo selection and issue creation
              // This will use the token securely from the backend, not exposing it in frontend
            } catch (error) {
              console.error('Error:', error);
            }
          }
          
          init();
        </script>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Error serving issue creator page:', error);
    res.status(500).send('An error occurred');
  }
});
// Auth routes for Electron
app.get("/auth/github-electron", (req, res) => {
  // Generate a unique state parameter
  const state = crypto.randomBytes(16).toString('hex');
 
  // Store state in a cookie that the client can send back
  res.cookie('github_auth_state', state, {
    httpOnly: true,
    maxAge: 10 * 60 * 1000, // 10 minutes expiry
    sameSite: process.env.NODE_ENV === "production" ? 'none' : 'lax',
    secure: process.env.NODE_ENV === "production"
  });
 
  // Add a more specific redirect_uri for electron clients
  const authUrl = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=user:email,repo&state=${state}&redirect_uri=${GITHUB_CALLBACK_URL}`;
 
  // Return CORS headers for Electron
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  
  // Respond with the auth URL and state (so Electron can store it locally)
  res.json({
    authUrl: authUrl,
    state: state
  });
});

// Standard GitHub auth flow
app.get("/auth/github", (req, res, next) => {
  // Store the client type and return URL
  req.session.clientType = req.query.client || "web";
  req.session.returnTo = req.query.returnTo || "/";
  // Store the redirectUri if provided (for development mode)
  req.session.redirectUri = req.query.redirectUri || null;

  // Generate state parameter for security
  const state = crypto.randomBytes(16).toString("hex");
  req.session.authState = state;

  // Pass the state parameter to GitHub
  passport.authenticate("github", {
    scope: ["user:email", "repo"],
    state: state,
  })(req, res, next);
});

// GitHub callback handler
// GitHub callback handler
app.get("/auth/github/callback", 
  passport.authenticate("github", { failureRedirect: "/login" }),
  async (req, res) => {
    try {
      const user = req.user;
      const responseData = {
        token: user.githubToken,
        user: {
          id: user.githubId,
          username: user.username,
          avatar: user.avatar
        }
      };

      // Check if this is an Electron client
      const clientType = req.session.clientType || req.query.client || "web";
      console.log("Client type:", clientType);

      if (clientType === "electron") {
        // Electron handling (keep this as is)
        // ...existing code for electron...
      } else {
        // For web, ALWAYS use the redirectUri if it was provided in the initial request
        let frontendUrl;
        
        if (req.session.redirectUri) {
          frontendUrl = req.session.redirectUri;
          console.log("Using custom redirect URI:", frontendUrl);
        } else {
          frontendUrl = process.env.NODE_ENV === "production" 
            ? "https://cloudpatch-frontend.onrender.com" 
            : "http://localhost:3000";
          console.log("Using environment-based redirect:", frontendUrl);
        }
        
        const queryParams = new URLSearchParams({
          token: user.githubToken,
          userData: JSON.stringify(responseData.user),
          returnTo: req.session.returnTo || "/",
        }).toString();

        return res.redirect(`${frontendUrl}?${queryParams}`);
      }
    } catch (error) {
      console.error("Callback error:", error);
      res.status(500).send(`Authentication Error: ${error.message}`);
    }
  }
);
// Token exchange for Electron apps
app.post("/auth/token-exchange", async (req, res) => {
  try {
    const { code, state } = req.body;
    
    console.log("Token exchange attempt with:", {
      codeProvided: !!code,
      stateProvided: !!state,
      userAgent: req.headers['user-agent']
    });
    
    if (!code) {
      return res.status(400).json({ error: "Authorization code is required" });
    }
    
    // Exchange the code for an access token
    console.log("Making GitHub token request with code:", 
      code ? code.substring(0, 4) + "..." : "missing");
    
    // Use node-fetch explicitly with proper error handling
    const https = require('https');
    const agent = new https.Agent({
      rejectUnauthorized: true,
      timeout: 60000
    });
    
    try {
      // First attempt to get the token
      const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
          "User-Agent": "Electron GitHub OAuth Client"
        },
        body: JSON.stringify({
          client_id: GITHUB_CLIENT_ID,
          client_secret: GITHUB_CLIENT_SECRET,
          code: code,
          redirect_uri: GITHUB_CALLBACK_URL
        }),
        agent: agent,
        timeout: 30000 // 30 second timeout
      });
      
      // Handle non-200 responses
      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        console.error("GitHub token error:", tokenResponse.status, errorText);
        return res.status(tokenResponse.status).json({ 
          error: `GitHub returned ${tokenResponse.status}`,
          details: errorText
        });
      }
      
      // Check for content type to handle non-JSON responses
      const contentType = tokenResponse.headers.get("content-type");
      let tokenData;
      
      if (contentType && contentType.includes("application/json")) {
        tokenData = await tokenResponse.json();
      } else {
        const textResponse = await tokenResponse.text();
        console.log("Non-JSON response from GitHub:", textResponse);
        
        // Try to parse URL-encoded response
        try {
          const params = new URLSearchParams(textResponse);
          tokenData = {
            access_token: params.get("access_token"),
            token_type: params.get("token_type"),
            scope: params.get("scope")
          };
        } catch (parseErr) {
          console.error("Failed to parse response:", parseErr);
          return res.status(500).json({ 
            error: "Invalid response format from GitHub",
            rawResponse: textResponse.substring(0, 100) // Include part of the response for debugging
          });
        }
      }
      
      if (!tokenData || !tokenData.access_token) {
        return res.status(400).json({ 
          error: "Failed to get access token",
          response: tokenData
        });
      }
      
      // Get user data from GitHub
      const userResponse = await fetch("https://api.github.com/user", {
        headers: {
          "Authorization": `Bearer ${tokenData.access_token}`,
          "User-Agent": "Electron GitHub OAuth Client",
          "Accept": "application/vnd.github.v3+json"
        },
        agent: agent,
        timeout: 30000
      });
      
      if (!userResponse.ok) {
        const errorText = await userResponse.text();
        console.error("GitHub user API error:", userResponse.status, errorText);
        return res.status(userResponse.status).json({ 
          error: `GitHub API error: ${userResponse.status}`,
          details: errorText
        });
      }
      
      const userData = await userResponse.json();
      
      if (!userData || !userData.id) {
        return res.status(500).json({ error: "Invalid user data received from GitHub" });
      }
      
      // Save or update user in the database
      let user = await User.findOne({ githubId: userData.id.toString() });
      
      if (user) {
        user.githubToken = tokenData.access_token;
        user.lastLogin = new Date();
        await user.save();
      } else {
        user = await new User({
          githubId: userData.id.toString(),
          username: userData.login,
          githubToken: tokenData.access_token,
          avatar: userData.avatar_url,
          email: userData.email
        }).save();
      }
      
      // Return the auth data
      return res.json({
        token: tokenData.access_token,
        user: {
          id: userData.id,
          username: userData.login,
          avatar: userData.avatar_url
        }
      });
    } catch (fetchError) {
      // Detailed error reporting
      console.error("Fetch error details:", {
        name: fetchError.name,
        message: fetchError.message,
        stack: fetchError.stack
      });
      
      if (fetchError.code === 'ECONNRESET' || fetchError.code === 'ETIMEDOUT') {
        return res.status(504).json({ 
          error: "Connection to GitHub timed out. Please check your network and try again.",
          errorCode: fetchError.code
        });
      }
      
      return res.status(500).json({ 
        error: "Failed to connect to GitHub", 
        message: fetchError.message,
        code: fetchError.code || 'unknown'
      });
    }
  } catch (error) {
    console.error("Token exchange error:", error);
    res.status(500).json({ 
      error: "Token exchange failed", 
      message: error.message,
      stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
    });
  }
});

// Token validation endpoint
app.get("/api/validate-token", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : null;
    
    if (!token) {
      console.log("Missing token in validation request");
      return res.status(401).json({ 
        valid: false, 
        message: "No token provided" 
      });
    }
    
    console.log(`Validating token: ${token.substring(0, 5)}...`);
    
    // Check if token exists in the database
    const user = await User.findOne({ githubToken: token });
    
    if (!user) {
      console.log("Token not found in database");
      return res.status(401).json({ 
        valid: false, 
        message: "Token not found in database" 
      });
    }
    
    // Verify with GitHub that the token is still valid
    try {
      const octokit = new Octokit({ auth: token });
      const githubUser = await octokit.users.getAuthenticated();
      
      console.log(`Token validated for user: ${githubUser.data.login}`);
      
      // Return user data with token validation
      return res.json({
        valid: true,
        user: {
          id: user.githubId,
          username: user.username,
          avatar: user.avatar
        }
      });
    } catch (githubError) {
      console.error("GitHub validation error:", githubError.message);
      return res.status(401).json({ 
        valid: false, 
        message: "GitHub API rejected the token",
        error: githubError.message
      });
    }
  } catch (error) {
    console.error("Token validation error:", error);
    res.status(500).json({
      valid: false,
      message: "Server error during token validation",
      error: error.message
    });
  }
});

// User API routes
app.get("/api/current_user", (req, res) => {
  if (req.isAuthenticated()) {
    const user = req.user;
    res.json({
      id: user.githubId,
      username: user.username,
      avatar: user.avatar,
      token: user.githubToken
    });
  } else {
    res.status(401).json({ error: "Not authenticated" });
  }
});

app.get("/api/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: "Logout failed" });
    }
    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        return res.status(500).json({ error: "Session destruction failed" });
      }
      res.clearCookie('connect.sid');
      res.json({ message: "Logged out successfully" });
    });
  });
});

// GitHub API routes
app.get("/api/user/repos", isAuthenticated, async (req, res) => {
  try {
    const octokit = new Octokit({ auth: req.user.githubToken });
    const { data } = await octokit.repos.listForAuthenticatedUser();
    res.json(data);
  } catch (error) {
    console.error("Error fetching repositories:", error);
    res.status(500).json({ error: "Failed to fetch repositories" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something broke!" });
});

// Add a simple root route to confirm the server is running
app.get("/", (req, res) => {
  res.send("CloudPatch API is running!");
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
