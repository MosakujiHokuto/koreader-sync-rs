DROP TABLE IF EXISTS progress;
DROP TABLE IF EXISTS users;
CREATE TABLE users (
       id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
       name TEXT UNIQUE,
       password TEXT
);

CREATE TABLE progress (
       id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
       document TEXT,
       user_id INTEGER,
       device_id TEXT,
       device TEXT,
       progress TEXT,
       percentage REAL,
       timestamp REAL,
       FOREIGN KEY(user_id) REFERENCES users(id),
       UNIQUE(document, user_id)
);
