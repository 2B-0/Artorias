console.log('=== SERVER.JS STARTED ===');
const express = require('express');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// JWT Secret - CHANGE THIS IN PRODUCTION!
const JWT_SECRET = process.env.JWT_SECRET || 'cinedb-jwt-secret-key-2024-change-in-production';

// CORS - Allow your frontend
app.use(cors({
    origin: 'https://artorias-2.netlify.app',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Authorization']
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../frontend')));

// Debug middleware
app.use((req, res, next) => {
    console.log(req.method, req.path);
    console.log('Authorization Header:', req.headers.authorization);
    next();
});

app.use('/posters', express.static('posters'));

// ===== AUTH MIDDLEWARE =====
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        return res.status(401).send('No token provided');
    }

    const token = authHeader.replace('Bearer ', '');
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        req.username = decoded.username;
        next();
    } catch (error) {
        console.error('Token verification error:', error.message);
        return res.status(401).send('Invalid or expired token');
    }
}

// ===== AUTH ROUTES =====

// Register
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).send('All fields required');
    }

    if (username.length < 3) {
        return res.status(400).send('Username must be at least 3 characters');
    }

    if (password.length < 6) {
        return res.status(400).send('Password must be at least 6 characters');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
        [username, email, hashedPassword],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).send('Username or email already exists');
                }
                console.error('Registration error:', err);
                return res.status(500).send('Error registering user');
            }
            res.json({ message: 'User registered successfully!' });
        }
    );
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).send('Email and password required');
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error');
        }
        
        if (!user) {
            return res.status(400).send('User not found');
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        
        if (!isMatch) {
            return res.status(400).send('Incorrect password');
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user.id,
                username: user.username,
                email: user.email
            },
            JWT_SECRET,
            { expiresIn: '7d' } // Token expires in 7 days
        );

        console.log('Login successful for:', user.username);
        
        res.json({ 
            token: token,
            username: user.username,
            email: user.email,
            message: 'Login successful!'
        });
    });
});

// Logout (client-side will remove token)
app.post('/api/logout', (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

// ===== MOVIES ROUTES =====
app.get('/api/movies', authMiddleware, (req, res) => {
    const query = `SELECT * FROM movies ORDER BY date_added DESC`;
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Get movies error:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json({ data: rows });
    });
});

app.get('/api/movies/:id', authMiddleware, (req, res) => {
    const { id } = req.params;
    db.get('SELECT * FROM movies WHERE id = ?', [id], (err, row) => {
        if (err) {
            console.error('Get movie error:', err);
            return res.status(500).json({ error: err.message });
        }
        if (!row) return res.status(404).send('Movie not found');
        res.json({ data: row });
    });
});

// Update movie poster
app.put('/api/movies/:id/poster', authMiddleware, (req, res) => {
    const { id } = req.params;
    const { poster_url } = req.body;

    db.run(
        'UPDATE movies SET poster_url = ? WHERE id = ?',
        [poster_url, id],
        function(err) {
            if (err) {
                console.error('Update poster error:', err);
                return res.status(500).send('Error updating poster');
            }
            res.json({ message: 'Poster updated successfully' });
        }
    );
});

// ===== REVIEWS ROUTES =====
app.post('/api/reviews', authMiddleware, (req, res) => {
    const { movie_id, rating, review_text } = req.body;
    const user_id = req.userId;

    if (!movie_id || !rating) {
        return res.status(400).send('Movie ID and rating required');
    }
    
    if (rating < 1 || rating > 5) {
        return res.status(400).send('Rating must be between 1-5');
    }

    // Check if user already reviewed this movie
    db.get(
        'SELECT * FROM reviews WHERE user_id = ? AND movie_id = ?',
        [user_id, movie_id],
        (err, existingReview) => {
            if (err) {
                console.error('Check review error:', err);
                return res.status(500).send('Database error');
            }

            if (existingReview) {
                // Update existing review
                db.run(
                    'UPDATE reviews SET rating = ?, review_text = ? WHERE id = ?',
                    [rating, review_text, existingReview.id],
                    function(err) {
                        if (err) {
                            console.error('Update review error:', err);
                            return res.status(500).send('Error updating review');
                        }
                        res.json({ message: 'Review updated!' });
                    }
                );
            } else {
                // Create new review
                db.run(
                    'INSERT INTO reviews (user_id, movie_id, rating, review_text) VALUES (?, ?, ?, ?)',
                    [user_id, movie_id, rating, review_text],
                    function(err) {
                        if (err) {
                            console.error('Create review error:', err);
                            return res.status(500).send('Error saving review');
                        }
                        res.json({ message: 'Review saved!' });
                    }
                );
            }
        }
    );
});

// DELETE review
app.delete('/api/reviews/:id', authMiddleware, (req, res) => {
    const { id } = req.params;
    const user_id = req.userId;

    db.get('SELECT * FROM reviews WHERE id = ? AND user_id = ?', [id, user_id], (err, row) => {
        if (err) {
            console.error('Check review error:', err);
            return res.status(500).send('Database error');
        }
        
        if (!row) {
            return res.status(404).send('Review not found or unauthorized');
        }

        db.run('DELETE FROM reviews WHERE id = ?', [id], function(err) {
            if (err) {
                console.error('Delete review error:', err);
                return res.status(500).send('Error deleting review');
            }
            res.json({ message: 'Review deleted successfully!' });
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
        if (err) {
            console.error('Get reviews error:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json({ data: rows });
    });
});

// ===== WATCHLIST ROUTES =====
app.get('/api/watchlist', authMiddleware, (req, res) => {
    const user_id = req.userId;
    
    const query = `
        SELECT m.*, w.status, w.date_added as watchlist_date 
        FROM watchlist w 
        JOIN movies m ON w.movie_id = m.id 
        WHERE w.user_id = ? 
        ORDER BY w.date_added DESC
    `;
    
    db.all(query, [user_id], (err, rows) => {
        if (err) {
            console.error('Get watchlist error:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json({ data: rows });
    });
});

app.post('/api/watchlist', authMiddleware, (req, res) => {
    const { movie_id, status } = req.body;
    const user_id = req.userId;

    if (!movie_id) {
        return res.status(400).send('Movie ID required');
    }

    db.get(
        'SELECT * FROM watchlist WHERE user_id = ? AND movie_id = ?',
        [user_id, movie_id],
        (err, row) => {
            if (err) {
                console.error('Check watchlist error:', err);
                return res.status(500).send('Database error');
            }
            
            if (row) {
                return res.status(400).send('Movie already in watchlist');
            }

            db.run(
                'INSERT INTO watchlist (user_id, movie_id, status) VALUES (?, ?, ?)',
                [user_id, movie_id, status || 'planned'],
                function(err) {
                    if (err) {
                        console.error('Add watchlist error:', err);
                        return res.status(500).send('Error adding to watchlist');
                    }
                    res.json({ message: 'Added to watchlist!' });
                }
            );
        }
    );
});

app.delete('/api/watchlist/:movie_id', authMiddleware, (req, res) => {
    const { movie_id } = req.params;
    const user_id = req.userId;

    db.run(
        'DELETE FROM watchlist WHERE user_id = ? AND movie_id = ?',
        [user_id, movie_id],
        function(err) {
            if (err) {
                console.error('Remove watchlist error:', err);
                return res.status(500).send('Error removing from watchlist');
            }
            if (this.changes === 0) {
                return res.status(404).send('Not found in watchlist');
            }
            res.json({ message: 'Removed from watchlist!' });
        }
    );
});

app.put('/api/watchlist/:movie_id/status', authMiddleware, (req, res) => {
    const { movie_id } = req.params;
    const { status } = req.body;
    const user_id = req.userId;

    if (!['planned', 'watching', 'watched'].includes(status)) {
        return res.status(400).send('Invalid status');
    }

    db.run(
        'UPDATE watchlist SET status = ? WHERE user_id = ? AND movie_id = ?',
        [status, user_id, movie_id],
        function(err) {
            if (err) {
                console.error('Update status error:', err);
                return res.status(500).send('Error updating status');
            }
            if (this.changes === 0) {
                return res.status(404).send('Not in watchlist');
            }
            res.json({ message: 'Status updated!' });
        }
    );
});

app.get('/api/watched', authMiddleware, (req, res) => {
    const user_id = req.userId;
    
    const query = `
        SELECT m.*, w.date_added as watched_date 
        FROM watchlist w 
        JOIN movies m ON w.movie_id = m.id 
        WHERE w.user_id = ? AND w.status = 'watched'
        ORDER BY w.date_added DESC
    `;
    
    db.all(query, [user_id], (err, rows) => {
        if (err) {
            console.error('Get watched error:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json({ data: rows });
    });
});

app.get('/api/watching', authMiddleware, (req, res) => {
    const user_id = req.userId;
    
    const query = `
        SELECT m.*, w.date_added 
        FROM watchlist w 
        JOIN movies m ON w.movie_id = m.id 
        WHERE w.user_id = ? AND w.status = 'watching'
        ORDER BY w.date_added DESC
    `;
    
    db.all(query, [user_id], (err, rows) => {
        if (err) {
            console.error('Get watching error:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json({ data: rows });
    });
});

// ===== STATS ROUTES =====
app.get('/api/stats', authMiddleware, (req, res) => {
    const user_id = req.userId;
    
    const stats = {};
    
    db.get('SELECT COUNT(*) as count FROM reviews WHERE user_id = ?', [user_id], (err, row) => {
        if (err) {
            console.error('Stats error:', err);
            return res.status(500).send('Database error');
        }
        stats.total_reviews = row.count;
        
        db.get('SELECT COUNT(*) as count FROM watchlist WHERE user_id = ?', [user_id], (err, row) => {
            if (err) return res.status(500).send('Database error');
            stats.watchlist_count = row.count;
            
            db.get('SELECT AVG(rating) as avg FROM reviews WHERE user_id = ?', [user_id], (err, row) => {
                if (err) return res.status(500).send('Database error');
                stats.avg_rating = row.avg ? row.avg.toFixed(1) : 0;
                
                res.json({ data: stats });
            });
        });
    });
});

// ===== FRIENDS ROUTES =====
app.get('/api/users/search', authMiddleware, (req, res) => {
    const { query } = req.query;
    const user_id = req.userId;
    
    db.all(
        'SELECT id, username, email FROM users WHERE (username LIKE ? OR email LIKE ?) AND id != ? LIMIT 10',
        [`%${query}%`, `%${query}%`, user_id],
        (err, rows) => {
            if (err) {
                console.error('Search users error:', err);
                return res.status(500).send('Database error');
            }
            res.json({ data: rows });
        }
    );
});

app.post('/api/friends/request', authMiddleware, (req, res) => {
    const { friend_id } = req.body;
    const user_id = req.userId;

    if (user_id === friend_id) {
        return res.status(400).send('Cannot add yourself as friend');
    }

    db.get(
        'SELECT * FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
        [user_id, friend_id, friend_id, user_id],
        (err, row) => {
            if (err) {
                console.error('Check friendship error:', err);
                return res.status(500).send('Database error');
            }

            if (row) {
                return res.status(400).send('Friend request already exists');
            }

            db.run(
                'INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)',
                [user_id, friend_id, 'pending'],
                function(err) {
                    if (err) {
                        console.error('Send friend request error:', err);
                        return res.status(500).send('Error sending request');
                    }
                    res.json({ message: 'Friend request sent!' });
                }
            );
        }
    );
});

app.get('/api/friends', authMiddleware, (req, res) => {
    const user_id = req.userId;
    
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
        if (err) {
            console.error('Get friends error:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json({ data: rows });
    });
});

app.get('/api/friends/pending', authMiddleware, (req, res) => {
    const user_id = req.userId;
    
    const query = `
        SELECT u.id as user_id, u.username, u.email, f.date_added
        FROM friends f
        JOIN users u ON f.user_id = u.id
        WHERE f.friend_id = ? AND f.status = 'pending'
    `;
    
    db.all(query, [user_id], (err, rows) => {
        if (err) {
            console.error('Get pending requests error:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json({ data: rows });
    });
});

app.put('/api/friends/accept/:friend_id', authMiddleware, (req, res) => {
    const { friend_id } = req.params;
    const user_id = req.userId;

    db.run(
        'UPDATE friends SET status = ? WHERE user_id = ? AND friend_id = ?',
        ['accepted', friend_id, user_id],
        function(err) {
            if (err) {
                console.error('Accept friend error:', err);
                return res.status(500).send('Error accepting request');
            }
            res.json({ message: 'Friend request accepted!' });
        }
    );
});

app.delete('/api/friends/reject/:friend_id', authMiddleware, (req, res) => {
    const { friend_id } = req.params;
    const user_id = req.userId;

    db.run(
        'DELETE FROM friends WHERE user_id = ? AND friend_id = ?',
        [friend_id, user_id],
        function(err) {
            if (err) {
                console.error('Reject friend error:', err);
                return res.status(500).send('Error rejecting request');
            }
            res.json({ message: 'Friend request rejected' });
        }
    );
});

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
        if (err) {
            console.error('Get friend reviews error:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json({ data: rows });
    });
});

// ===== TMDB ROUTES (Optional - for poster fetching) =====
app.get('/api/tmdb/search/:title', authMiddleware, (req, res) => {
    // This is a placeholder - you'd need to implement TMDB API integration
    res.json({ poster_url: null });
});

// Change password
app.post('/api/change-password', authMiddleware, async (req, res) => {
    const { newPassword } = req.body;
    const userId = req.userId;

    if (!newPassword || newPassword.length < 6) {
        return res.status(400).send('Password must be at least 6 characters');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    db.run(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        [hashedPassword, userId],
        function(err) {
            if (err) {
                console.error('Change password error:', err);
                return res.status(500).send('Error updating password');
            }
            res.json({ message: 'Password updated successfully!' });
        }
    );
});

// Root route
app.get('/', (req, res) => {
    res.json({ 
        message: 'CineDB API Server',
        status: 'running',
        auth: 'JWT Token-based',
        endpoints: {
            auth: '/api/login, /api/register, /api/logout',
            movies: '/api/movies',
            reviews: '/api/reviews',
            watchlist: '/api/watchlist',
            stats: '/api/stats',
            friends: '/api/friends'
        }
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`✅ JWT Authentication enabled`);
    console.log(`✅ CORS enabled for https://artorias-2.netlify.app`);
});