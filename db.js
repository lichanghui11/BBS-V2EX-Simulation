//这个文件实际上并没有用， 数据库是在命令行完成的

const Database = require('better-sqlite3');
const path = require('node:path');

//指定数据库的文件路径，若不存在则自动创建
const DB_PATH = path.join(__dirname, './data/bbs.db');

let db;

function initDatabase() {
  //初始化数据库的函数
  db = new Database(DB_PATH);
  console.log('[DB] 成功连接到 bbs.db(better-sqlite3!!!)')

  //执行建表
  // 1)users 表
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      userId INTEGER PRIMARY KEY AUTOINCREMENT,
      accountName TEXT NOT NULL UNIQUE,
      passwordHash TEXT NOT NULL,
      salt TEXT NOT NULL,
      email TEXT NOT NULL,
      tel TEXT,
      avatarUrl TEXT
    )
  `).run()

  //2)posts 表
  db.prepare(`
    CREATE TABLE IF NOT EXISTS posts (
      postId INTEGER PRIMARY KEY AUTOINCREMENT,
      createdAt TEXT NOT NULL,
      createdBy INTEGER NOT NULL,
      postTitle TEXT NOT NULL,
      postContent TEXT NOT NULL,
      ip TEXT NOT NULL,
      isDeleted BOOLEAN DEFAULT 0,
      deletedAt TEXT
    )
  `).run()

  //3) comments 表
  db.prepare(`
    CREATE TABLE IF NOT EXISTS comments (
      commentId INTEGER PRIMARY KEY AUTOINCREMENT,
      commentContent TEXT NOT NULL,
      postId INTEGER NOT NULL,
      createdAt TEXT NOT NULL,
      createdBy INTEGER NOT NULL,
      ip TEXT NOT NULL,
      isDeleted BOOLEAN DEFAULT 0,
      deletedAt TEXT
    )
  `).run()
}

//在路由中通过 getDb() 来访问数据库实例
function getDb() {
  if (!db) {
    throw new Error('[DB] 数据库尚未初始化，请先调用 initDatabase()');
  } else {
    return db;
  }
}

module.exports = {
  initDatabase,
  getDb,
}