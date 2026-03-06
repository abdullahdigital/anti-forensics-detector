require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const config = require('./config/index.js');
const db = require('./db/services/SQLiteService.js');

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Basic Route
app.get('/', (req, res) =\u003e {
  res.send('ForenX Express Backend is running!');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =\u003e {
  console.log(`Express server listening on port ${PORT}`);
});
