// interfaces/IDatabaseService.js
class IDatabaseService {
  async saveUser(userData) {
    throw new Error('Method 'saveUser()' not implemented.');
  }

  async getUserById(userId) {
    throw new Error('Method 'getUserById()' not implemented.');
  }

  async saveEvidenceAnalysis(analysisData) {
    throw new Error('Method 'saveEvidenceAnalysis()' not implemented.');
  }

  async getReportsByUser(userId) {
    throw new Error('Method 'getReportsByUser()' not implemented.');
  }

  // Add other common database operations here
}

module.exports = IDatabaseService;