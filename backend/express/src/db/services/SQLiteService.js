const IDatabaseService = require('../interfaces/IDatabaseService');
const sqlite3 = require('sqlite3').verbose();

class SQLiteDatabaseService extends IDatabaseService {
  constructor() {
    super();
    this.db = new sqlite3.Database('./forenx.db', (err) =\u003e {
      if (err) {
        console.error('Error connecting to SQLite database:', err.message);
      } else {
        console.log('Connected to the SQLite database.');
        this.initDb();
      }
    });
  }

  initDb() {
    this.db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )`);
    this.db.run(`CREATE TABLE IF NOT EXISTS evidence_analysis (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      fileName TEXT,
      metadata TEXT,
      hashes TEXT,
      aiSummary TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id)
    )`);
    this.db.run(`CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      reportType TEXT,
      reportPath TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id)
    )`);
  }

  async saveUser(userData) {
    return new Promise((resolve, reject) =\u003e {
      this.db.run(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [userData.username, userData.password],
        function (err) {
          if (err) {
            reject(err);
          } else {
            resolve({ id: this.lastID, ...userData });
          }
        }
      );
    });
  }

  async getUserById(userId) {
    return new Promise((resolve, reject) =\u003e {
      this.db.get(
        'SELECT id, username FROM users WHERE id = ?',
        [userId],
        (err, row) =\u003e {
          if (err) {
            reject(err);
          } else {
            resolve(row);
          }
        }
      );
    });
  }

  async saveEvidenceAnalysis(analysisData) {
    return new Promise((resolve, reject) =\u003e {
      this.db.run(
        'INSERT INTO evidence_analysis (userId, fileName, metadata, hashes, aiSummary) VALUES (?, ?, ?, ?, ?)',
        [
          analysisData.userId,
          analysisData.fileName,
          JSON.stringify(analysisData.metadata),
          JSON.stringify(analysisData.hashes),
          analysisData.aiSummary,
        ],
        function (err) {
          if (err) {
            reject(err);
          } else {
            resolve({ id: this.lastID, ...analysisData });
          }
        }
      );
    });
  }

  async getReportsByUser(userId) {
    return new Promise((resolve, reject) =\u003e {
      this.db.all(
        'SELECT * FROM reports WHERE userId = ?',
        [userId],
        (err, rows) =\u003e {
          if (err) {
            reject(err);
          } else {
            resolve(rows);
          }
        }
      );
    });
  }

  // Add other SQLite specific implementations for other methods in IDatabaseService
}

module.exports = SQLiteDatabaseService;