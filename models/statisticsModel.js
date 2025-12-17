const mongoose = require('mongoose');

const monthlyStatsSchema = new mongoose.Schema({
  totalEarned: { type: Number, default: 0.0, required: true },
  totalPurchases: { type: Number, default: 0, required: true },
  totalSiteVisits: { type: Number, default: 0, required: true },
  userJoins: { type: Number, default: 0, required: true }
}, { _id: false });

const yearlyStatsSchema = new mongoose.Schema({
  year: {
    type: Number,
    required: true
  },
  months: {
    type: [monthlyStatsSchema],
    default: () => Array(12).fill({ totalEarned: 0, totalPurchases: 0, userJoins: 0, totalSiteVisits: 0 })
  }
}, { _id: false });

const statisticsSchema = new mongoose.Schema({
  totalPurchases: { type: Number, default: 0, required: true },
  totalEarned: { type: Number, default: 0.0, required: true },
  totalSiteVisits: { type: Number, default: 0, required: true },
  yearlyStats: { type: [yearlyStatsSchema], default: [] },
  lastUpdated: { type: Date, default: Date.now }
});

// Static method to get or create the statistics document
statisticsSchema.statics.getStatistics = async function() {
  let stats = await this.findOne();
  if (!stats) {
    stats = await this.create({});
  }
  return stats;
};

module.exports = mongoose.model('Statistics', statisticsSchema);
