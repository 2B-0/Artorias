const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fetch = require('node-fetch'); // npm i node-fetch@2

const TMDB_API_KEY = '8cc56cc2e9667f87435a260a471d7f28';
const TMDB_API_URL = 'https://api.themoviedb.org/3';
const POSTER_BASE_URL = 'https://image.tmdb.org/t/p/w500';

// Create database connection
const dbPath = path.resolve(__dirname, 'movies.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Error opening database:', err.message);
    else {
        console.log('Connected to SQLite database');
        initDatabase();
    }
});

// Initialize tables
function initDatabase() {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, () => console.log('Users table ready'));

    db.run(`
        CREATE TABLE IF NOT EXISTS movies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            year INTEGER,
            director TEXT,
            runtime INTEGER,
            genre TEXT,
            type TEXT NOT NULL,
            synopsis TEXT,
            poster_url TEXT,
            date_added DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, () => console.log('Movies table ready'));

    db.run(`
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            movie_id INTEGER NOT NULL,
            rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
            review_text TEXT,
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE
        )
    `, () => console.log('Reviews table ready'));

    db.run(`
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            movie_id INTEGER NOT NULL,
            status TEXT DEFAULT 'planned',
            date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE
        )
    `, () => {
        console.log('Watchlist table ready');
        insertTMDBMovies();
    });
}
db.run(`
    CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, friend_id)
    )
`, () => console.log('Friends table ready'));

// Fetch movie details from TMDB
// Fetch movie details from TMDB
async function fetchMovieDetails(id) {
    try {
        const [movieRes, creditsRes] = await Promise.all([
            fetch(`${TMDB_API_URL}/movie/${id}?api_key=${TMDB_API_KEY}&language=en-US`),
            fetch(`${TMDB_API_URL}/movie/${id}/credits?api_key=${TMDB_API_KEY}`)
        ]);
        
        const movie = await movieRes.json();
        const credits = await creditsRes.json();
        
        return { ...movie, credits };
    } catch (error) {
        console.error('Error fetching movie details:', error.message);
        return null;
    }
}

// Insert TMDB movies
async function insertTMDBMovies() {
    db.get('SELECT COUNT(*) as count FROM movies', async (err, row) => {
        if (err) return console.error(err);
       if (row.count >= 100) {
    console.log(`Already have ${row.count} movies. Skipping fetch.`);
    return;
}

        console.log('Fetching movies from TMDB...');
        const totalPages = 50; // 5 pages x 20 movies = 100 movies
        let allMovies = [];

        for (let page = 1; page <= totalPages; page++) {
            const res = await fetch(`${TMDB_API_URL}/movie/popular?api_key=${TMDB_API_KEY}&language=en-US&page=${page}`);
            const data = await res.json();
            allMovies.push(...data.results);
        }

        const stmt = db.prepare(`
            INSERT INTO movies (title, year, director, runtime, genre, type, synopsis, poster_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `);

        for (const m of allMovies) {
    const details = await fetchMovieDetails(m.id);
    if (!details) continue;

    const title = details.title;
    const year = details.release_date ? parseInt(details.release_date.split('-')[0]) : null;
    const runtime = details.runtime || null;
    const genre = details.genres ? details.genres.map(g => g.name).join(', ') : '';
    const synopsis = details.overview || '';
    const poster_url = details.poster_path ? POSTER_BASE_URL + details.poster_path : null;
    const director = details.credits?.crew?.find(c => c.job === 'Director')?.name || 'Unknown';

    console.log(`Inserting: ${title} | Poster: ${poster_url ? 'YES' : 'NO'}`);

    stmt.run([title, year, director, runtime, genre, 'Movie', synopsis, poster_url], (err) => {
        if (err) console.error('Error inserting movie:', err.message);
    });
    
    // Add small delay to avoid rate limiting
    await new Promise(resolve => setTimeout(resolve, 100));
}

        stmt.finalize(() => console.log(`Inserted ${allMovies.length} movies from TMDB successfully.`));
    });
}

module.exports = db;
