module.exports = {
  PORT: process.env.PORT || 3000,
  DATABASE_TYPE: process.env.DATABASE_TYPE || 'sqlite', // 'sqlite' or 'mongodb'
  // Add other configurations like JWT secret, etc.
};