import { MongoClient } from 'mongodb';

export class MongoAdapter {
  constructor(uri, dbName = 'campus_cart', collectionName = 'lite_db') {
    this.uri = uri;
    this.dbName = dbName;
    this.collectionName = collectionName;
    this.client = null;
    this.data = null;
  }

  async _getCollection() {
    if (!this.client) {
      this.client = new MongoClient(this.uri, {});
      await this.client.connect();
    }
    const db = this.client.db(this.dbName);
    return db.collection(this.collectionName);
  }

  async read() {
    try {
      const col = await this._getCollection();
      const doc = await col.findOne({ _id: 'singleton' });
      this.data = doc?.data ?? null;
    } catch (e) {
      this.data = null;
    }
  }

  async write() {
    const col = await this._getCollection();
    await col.updateOne(
      { _id: 'singleton' },
      { $set: { data: this.data, updatedAt: new Date() } },
      { upsert: true }
    );
  }
}
