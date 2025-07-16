-- Database initialization script for API Integration Security Framework

-- Enable UUID extension for better primary keys (optional)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create database if not exists (already handled by POSTGRES_DB)
-- This file runs automatically when the container starts

-- Set timezone
SET timezone = 'UTC';

-- Create indexes for performance (these will be created by SQLAlchemy, but good to have)
-- Additional custom indexes can be added here

-- Insert demo data for development
-- This will be handled by the application, but could be added here for quick setup

-- Log successful initialization
INSERT INTO pg_stat_statements_info (dealloc) VALUES (0) ON CONFLICT DO NOTHING;

SELECT 'Database initialization completed' as status;
