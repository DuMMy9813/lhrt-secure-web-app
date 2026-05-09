DROP TABLE IF EXISTS healthRecords;
DROP TABLE IF EXISTS users;
DROP SEQUENCE IF EXISTS recordSeq;
DROP SEQUENCE IF EXISTS userSeq;

CREATE TABLE users (
    Id INT PRIMARY KEY,
    Username TEXT NOT NULL UNIQUE,
    PassHash TEXT NOT NULL,
    Email TEXT NOT NULL,
    FullName TEXT NOT NULL
);

CREATE SEQUENCE userSeq START 1;

CREATE TABLE healthRecords (
    Id INT PRIMARY KEY,
    UserId INT NOT NULL REFERENCES users(Id),
    RecordDate TEXT NOT NULL,
    WeightKg FLOAT NOT NULL,
    BloodPressure TEXT NOT NULL,
    HeartRate INT NOT NULL,
    Notes TEXT NOT NULL
);

CREATE SEQUENCE recordSeq START 1;

INSERT INTO users (Id, Username, PassHash, Email, FullName)
VALUES (1, 'admin', 'admin123', 'admin@example.com', 'Admin User');
