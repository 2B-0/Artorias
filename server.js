console.log('=== SERVER.JS STARTED ===');
const express = require('express');
const path=require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS - MUST be first
app.use(cors({
    origin: 'https://artorias-2.netlify.app',  // NO trailing slash
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
    exposedHeaders: ['Set-Cookie']
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname,'../frontend')));

// Replace your session middleware with:
const corsOptions = {
  origin: 'https://artorias-2.netlify.app', // your frontend URL
  credentials: true, // allows cookies to be sent
};
app.use(cors(corsOptions));

app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: './'
    }),
    secret: process.env.SESSION_SECRET || 'cinedb-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    name: 'cinedb.sid',
    proxy: true,  // Important for Render
    cookie: { 
        secure: true,
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000,
        sameSite: 'none',
        path: '/'
    }
}));
app.use((req,res,next)=> {
    if(req.session) {
        req.session.touch();
    }
    next();
});

// Debug middleware
app.use((req, res, next) => {
    console.log(req.method, req.path);
    console.log('Session:', req.sessionID);
    console.log('User:', req.session.userId);
    next();
});
// Rest of your routes...

app.use('/posters', express.static('posters'));
app.use(session({
    secret: 'your_secret_key_change_this_in_production',
    resave: true,
    saveUninitialized: true,
    cookie: { 
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
}));

// Add this debug middleware
app.use((req, res, next) => {
    console.log('Session ID:', req.sessionID);
    console.log('User ID in session:', req.session.userId);
    next();
});

// ===== AUTH ROUTES =====

// Register
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).send('All fields required');

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
        [username, email, hashedPassword],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).send('Username or email already exists');
                return res.status(500).send('Error registering user');
            }
            res.send('User registered successfully!');
        }
    );
});

// Login
// Login
// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) return res.status(500).send('Database error');
        if (!user) return res.status(400).send('User not found');

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(400).send('Incorrect password');

        req.session.userId = user.id;
        req.session.username = user.username;
        
        // Save session explicitly
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).send('Session error');
            }
            
            console.log('Session saved:', req.sessionID);
            console.log('User ID:', req.session.userId);
            
            res.json({ 
                message: 'Login successful!',
                username: user.username,
                email: user.email,
                sessionId: req.sessionID  // For debugging
            });
        });
    });
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).send('Error logging out');
        res.send('Logged out');
    });
});

// ===== AUTH MIDDLEWARE =====
function authMiddleware(req, res, next) {
    if (!req.session.userId) return res.status(401).send('Unauthorized');
    next();
}

// ===== MOVIES ROUTES =====
app.get('/api/movies', authMiddleware, (req, res) => {
    const query = `SELECT * FROM movies ORDER BY date_added DESC`;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ data: rows });
    });
});

app.get('/api/movies/:id', authMiddleware, (req, res) => {
    const { id } = req.params;
    db.get('SELECT * FROM movies WHERE id = ?', [id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).send('Movie not found');
        res.json({ data: row });
    });
});

// ===== REVIEWS ROUTES =====
app.post('/api/reviews', authMiddleware, (req, res) => {
    const { movie_id, rating, review_text } = req.body;
    const user_id = req.session.userId;

    if (!movie_id || !rating) return res.status(400).send('Movie ID and rating required');
    if (rating < 1 || rating > 5) return res.status(400).send('Rating must be between 1-5');

    db.run(
        'INSERT INTO reviews (user_id, movie_id, rating, review_text) VALUES (?, ?, ?, ?)',
        [user_id, movie_id, rating, review_text],
        function(err) {
            if (err) return res.status(500).send('Error saving review');
            res.send('Review saved!');
        }
    );
});
// DELETE review
app.delete('/api/reviews/:id', authMiddleware, (req, res) => {
    const { id } = req.params;
    const user_id = req.session.userId;

    // First check if the review belongs to the current user
    db.get('SELECT * FROM reviews WHERE id = ? AND user_id = ?', [id, user_id], (err, row) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        
        if (!row) {
            return res.status(404).send('Review not found or unauthorized');
        }

        // Delete the review
        db.run('DELETE FROM reviews WHERE id = ?', [id], function(err) {
            if (err) {
                return res.status(500).send('Error deleting review');
            }
            res.send('Review deleted successfully!');
        });
    });
});

app.get('/api/reviews/:movie_id', authMiddleware, (req, res) => {
    const { movie_id } = req.params;
    
    const query = `
        SELECT r.*, u.username 
        FROM reviews r 
        JOIN users u ON r.user_id = u.id 
        WHERE r.movie_id = ? 
        ORDER BY r.date_created DESC
    `;
    
    db.all(query, [movie_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ data: rows });
    });
});

// ===== WATCHLIST ROUTES =====
app.get('/api/watchlist', authMiddleware, (req, res) => {
    const user_id = req.session.userId;
    
    const query = `
        SELECT m.*, w.status, w.date_added as watchlist_date 
        FROM watchlist w 
        JOIN movies m ON w.movie_id = m.id 
        WHERE w.user_id = ? 
        ORDER BY w.date_added DESC
    `;
    
    db.all(query, [user_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ data: rows });
    });
});
// Update watchlist status
app.put('/api/watchlist/:movie_id/status', authMiddleware, (req, res) => {
    const { movie_id } = req.params;
    const { status } = req.body; // 'planned', 'watching', 'watched'
    const user_id = req.session.userId;

    if (!['planned', 'watching', 'watched'].includes(status)) {
        return res.status(400).send('Invalid status');
    }

    db.run(
        'UPDATE watchlist SET status = ? WHERE user_id = ? AND movie_id = ?',
        [status, user_id, movie_id],
        function(err) {
            if (err) return res.status(500).send('Error updating status');
            if (this.changes === 0) return res.status(404).send('Not in watchlist');
            res.send('Status updated!');
        }
    );
});

// Get watched movies
app.get('/api/watched', authMiddleware, (req, res) => {
    const user_id = req.session.userId;
    
    const query = `
        SELECT m.*, w.date_added as watched_date 
        FROM watchlist w 
        JOIN movies m ON w.movie_id = m.id 
        WHERE w.user_id = ? AND w.status = 'watched'
        ORDER BY w.date_added DESC
    `;
    
    db.all(query, [user_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ data: rows });
    });
});

// Get currently watching
app.get('/api/watching', authMiddleware, (req, res) => {
    const user_id = req.session.userId;
    
    const query = `
        SELECT m.*, w.date_added 
        FROM watchlist w 
        JOIN movies m ON w.movie_id = m.id 
        WHERE w.user_id = ? AND w.status = 'watching'
        ORDER BY w.date_added DESC
    `;
    
    db.all(query, [user_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ data: rows });
    });
});
app.post('/api/watchlist', authMiddleware, (req, res) => {
    const { movie_id, status } = req.body;
    const user_id = req.session.userId;

    if (!movie_id) return res.status(400).send('Movie ID required');

    // Check if already in watchlist
    db.get(
        'SELECT * FROM watchlist WHERE user_id = ? AND movie_id = ?',
        [user_id, movie_id],
        (err, row) => {
            if (err) return res.status(500).send('Database error');
            if (row) return res.status(400).send('Movie already in watchlist');

            db.run(
                'INSERT INTO watchlist (user_id, movie_id, status) VALUES (?, ?, ?)',
                [user_id, movie_id, status || 'planned'],
                function(err) {
                    if (err) return res.status(500).send('Error adding to watchlist');
                    res.send('Added to watchlist!');
                }
            );
        }
    );
});

app.delete('/api/watchlist/:movie_id', authMiddleware, (req, res) => {
    const { movie_id } = req.params;
    const user_id = req.session.userId;

    db.run(
        'DELETE FROM watchlist WHERE user_id = ? AND movie_id = ?',
        [user_id, movie_id],
        function(err) {
            if (err) return res.status(500).send('Error removing from watchlist');
            if (this.changes === 0) return res.status(404).send('Not found in watchlist');
            res.send('Removed from watchlist!');
        }
    );
});

// ===== STATS ROUTES =====
app.get('/api/stats', authMiddleware, (req, res) => {
    const user_id = req.session.userId;
    
    const stats = {};
    
    // Total reviews
    db.get('SELECT COUNT(*) as count FROM reviews WHERE user_id = ?', [user_id], (err, row) => {
        if (err) return res.status(500).send('Database error');
        stats.total_reviews = row.count;
        
        // Watchlist count
        db.get('SELECT COUNT(*) as count FROM watchlist WHERE user_id = ?', [user_id], (err, row) => {
            if (err) return res.status(500).send('Database error');
            stats.watchlist_count = row.count;
            
            // Average rating
            db.get('SELECT AVG(rating) as avg FROM reviews WHERE user_id = ?', [user_id], (err, row) => {
                if (err) return res.status(500).send('Database error');
                stats.avg_rating = row.avg ? row.avg.toFixed(1) : 0;
                
                res.json({ data: stats });
            });
        });
    });
});
// Root route
app.get('/', (req, res) => {
    res.json({ 
        message: 'CineDB API Server',
        status: 'running',
        endpoints: {
            movies: '/api/movies',
            reviews: '/api/reviews',
            watchlist: '/api/watchlist',
            stats: '/api/stats'
        }
    });
});
// Change password
app.post('/api/change-password', authMiddleware, async (req, res) => {
    const { newPassword } = req.body;
    const userId = req.session.userId;

    if (!newPassword || newPassword.length < 6) {
        return res.status(400).send('Password must be at least 6 characters');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    db.run(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        [hashedPassword, userId],
        function(err) {
            if (err) return res.status(500).send('Error updating password');
            res.send('Password updated successfully!');
        }
    );
});
// Search users
app.get('/api/users/search', authMiddleware, (req, res) => {
    const { query } = req.query;
    const user_id = req.session.userId;
    
    db.all(
        'SELECT id, username, email FROM users WHERE (username LIKE ? OR email LIKE ?) AND id != ? LIMIT 10',
        [`%${query}%`, `%${query}%`, user_id],
        (err, rows) => {
            if (err) return res.status(500).send('Database error');
            res.json({ data: rows });
        }
    );
});
// Send friend request
app.post('/api/friends/request', authMiddleware, (req, res) => {
    const { friend_id } = req.body;
    const user_id = req.session.userId;

    // Prevent adding yourself
    if (user_id === friend_id) {
        return res.status(400).send('Cannot add yourself as friend');
    }

    // Check if friendship already exists
    db.get(
        'SELECT * FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
        [user_id, friend_id, friend_id, user_id],
        (err, row) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).send('Database error');
            }

            if (row) {
                return res.status(400).send('Friend request already exists');
            }

            // Insert new friend request
            db.run(
                'INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)',
                [user_id, friend_id, 'pending'],
                function(err) {
                    if (err) {
                        console.error('Friend request error:', err);
                        return res.status(500).send('Error sending request');
                    }
                    res.send('Friend request sent!');
                }
            );
        }
    );
});

// Get friends list
app.get('/api/friends', authMiddleware, (req, res) => {
    const user_id = req.session.userId;
    
    const query = `
        SELECT u.id, u.username, u.email, f.status, f.date_added
        FROM friends f
        JOIN users u ON (f.friend_id = u.id)
        WHERE f.user_id = ? AND f.status = 'accepted'
        UNION
        SELECT u.id, u.username, u.email, f.status, f.date_added
        FROM friends f
        JOIN users u ON (f.user_id = u.id)
        WHERE f.friend_id = ? AND f.status = 'accepted'
    `;
    
    db.all(query, [user_id, user_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ data: rows });
    });
});

// Accept friend request
app.put('/api/friends/accept/:friend_id', authMiddleware, (req, res) => {
    const { friend_id } = req.params;
    const user_id = req.session.userId;

    db.run(
        'UPDATE friends SET status = ? WHERE user_id = ? AND friend_id = ?',
        ['accepted', friend_id, user_id],
        function(err) {
            if (err) return res.status(500).send('Error accepting request');
            res.send('Friend request accepted!');
        }
    );
});
// Get pending friend requests (requests sent TO current user)
app.get('/api/friends/pending', authMiddleware, (req, res) => {
    const user_id = req.session.userId;
    
    const query = `
        SELECT u.id as user_id, u.username, u.email, f.date_added
        FROM friends f
        JOIN users u ON f.user_id = u.id
        WHERE f.friend_id = ? AND f.status = 'pending'
    `;
    
    db.all(query, [user_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ data: rows });
    });
});

// Reject friend request
app.delete('/api/friends/reject/:friend_id', authMiddleware, (req, res) => {
    const { friend_id } = req.params;
    const user_id = req.session.userId;

    db.run(
        'DELETE FROM friends WHERE user_id = ? AND friend_id = ?',
        [friend_id, user_id],
        function(err) {
            if (err) return res.status(500).send('Error rejecting request');
            res.send('Friend request rejected');
        }
    );
});

// Get friend's reviews
app.get('/api/friends/:friend_id/reviews', authMiddleware, (req, res) => {
    const { friend_id } = req.params;
    
    const query = `
        SELECT r.*, m.title as movie_title, m.year, m.poster_url, u.username
        FROM reviews r
        JOIN movies m ON r.movie_id = m.id
        JOIN users u ON r.user_id = u.id
        WHERE r.user_id = ?
        ORDER BY r.date_created DESC
    `;
    
    db.all(query, [friend_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ data: rows });
    });
});
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`✅ CORS enabled for http://localhost:5500`);
});