# UserCURD-JWT
This Golang backend provides JWT-based authentication with /login, /profile, /update-password, and /update-email endpoints. It includes middleware for JWT validation and error handling. A simple SQL user table stores essential fields. Email verification is skipped. Secure user authentication and updates are ensured

Go + PostgreSQL API Setup Guide

1. Install Go and Verify Environment Variables
  Install Go:
       Follow the official Go installation guide to install Go on your system.

2.Verify Go Installation:

   After installation, check if Go is installed correctly by running:
       go version
       go env GOROOT
       go env GOPATH

Ensure GOROOT points to the Go installation directory and GOPATH points to your workspace.

3. PostgreSQL Database Setup
   
Create a PostgreSQL Database:

Ensure PostgreSQL is installed. Start the database service and create a database:

CREATE DATABASE mydatabase;

Create users Table:

Run the following SQL command in your PostgreSQL instance:

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL
);
Sample Yarc Testing for Handlers You can use PostMan also:

 User-Registration---->  ![golang-registeration](https://github.com/user-attachments/assets/8d4220ff-e988-4570-9065-bc31e0f736dc)
 Login with Registered information ------> ![golang-login](https://github.com/user-attachments/assets/9a3736dd-3ba4-4bc9-9399-ffdbec9cbee6)
 Profile Listing With login token --------> ![golang profile](https://github.com/user-attachments/assets/49b6f688-4a58-4f7e-a3a5-eedc0647b032)
 Updating password with token -------> ![passwordUpdated](https://github.com/user-attachments/assets/e441a3da-b02c-45a0-b14f-8ebd6dfeccaa)
 Updating email with token ----------> ![emailupdate](https://github.com/user-attachments/assets/0fd9bef6-c2c0-4e2e-a5ac-9975f4c5d257)




