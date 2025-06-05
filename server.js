require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

async function getCollectionNames() {
  const db = mongoose.connection.db;
  const collections = await db.listCollections().toArray();
  return collections.map(c => c.name);
}

app.get('/', async (req, res) => {
  try {
    const collections = await getCollectionNames();
    res.json(collections);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get('/:collection', async (req, res) => {
  const collectionName = req.params.collection;
  const db = mongoose.connection.db;

  try {
    const exists = await db.listCollections({ name: collectionName }).hasNext();
    if (!exists) {
      return res.status(404).json({ error: `Collection '${collectionName}' not found` });
    }

    const quizzes = await db.collection(collectionName).find({}).toArray();
    res.json(quizzes);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch quizzes' });
  }
});


(async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      dbName: 'quizes',
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`✅ Connected to MongoDB ${mongoose.connection.name}`);

    app.listen(PORT, () => {
      console.log(`🚀 Server running at http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  }
})();
