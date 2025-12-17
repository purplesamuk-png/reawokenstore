const mongoose = require('mongoose');

const downloadSchema = new mongoose.Schema({
    productName: { type: String, required: true },
    discordUserId: { type: String, required: true },
    nonce: { type: String, required: true },
    downloadDate: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Download', downloadSchema);