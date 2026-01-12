-- Create a separate database for development/app use
CREATE DATABASE devdb;

ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'user';
