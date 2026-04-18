-- Lightweight Health Record Tracker - Database Schema
-- WARNING: This schema is intentionally minimal (no stored procedures, no parameterisation)
-- to demonstrate SQL-injection vulnerabilities in the PHP layer.

CREATE DATABASE IF NOT EXISTS health_tracker;
USE health_tracker;

CREATE TABLE users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(50)  NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,   -- stored as plain MD5 (vulnerable)
    email       VARCHAR(100) NOT NULL,
    full_name   VARCHAR(100) NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE health_records (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT          NOT NULL,
    record_date     DATE         NOT NULL,
    weight_kg       DECIMAL(5,2),
    blood_pressure  VARCHAR(20),          -- e.g. "120/80"
    heart_rate      INT,
    notes           TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Seed data (passwords are MD5 of "password123")
INSERT INTO users (username, password, email, full_name) VALUES
  ('alice',   MD5('password123'), 'alice@example.com', 'Alice Smith'),
  ('bob',     MD5('password123'), 'bob@example.com',   'Bob Jones'),
  ('admin',   MD5('admin'),       'admin@example.com', 'Administrator');

INSERT INTO health_records (user_id, record_date, weight_kg, blood_pressure, heart_rate, notes) VALUES
  (1, '2024-01-10', 65.5, '118/76', 72, 'Feeling good today'),
  (1, '2024-01-17', 65.2, '120/78', 74, 'Slight headache in morning'),
  (1, '2024-01-24', 64.8, '115/75', 70, 'Exercise routine going well'),
  (2, '2024-01-11', 80.1, '130/85', 80, 'Stressful week at work'),
  (2, '2024-01-18', 79.5, '128/82', 78, 'Better sleep this week');
