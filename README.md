# RBAC OpenAPI Project

A secure authentication system with Role-Based Access Control (RBAC) using JWT tokens.

## Features

- JWT token-based authentication with refresh tokens
- Role-based access control (RBAC)
- Secure cookie handling
- MongoDB integration
- User registration and login endpoints
- Token refresh mechanism
- Rate limiting for auth routes
- Admin user creation on first run

## Setup

1. Clone the repository
2. Set up environment variables:
   - In the `server` directory:
     ```bash
     cp .env.example .env
     ```
     Edit `.env` and update:
     - `JWT_SECRET`: A secure random string for JWT signing
     - `MONGO_URI`: Your MongoDB connection string
     - `ADMIN_PASSWORD`: Password for the default admin user
   
   - In the `client/src` directory:
     ```bash
     cp .env.example .env
     ```
     Edit `.env` and update:
     - `REACT_APP_API_URL`: URL of your backend server

3. Install dependencies:
   ```bash
   # Install server dependencies
   cd server
   npm install

   # Install client dependencies
   cd ../client
   npm install
   ```

4. Start the development servers:
   ```bash
   # Start the backend server
   cd server
   npm start

   # In a new terminal, start the frontend
   cd client
   npm start
   ```

## Security Notes

- Never commit `.env` files to version control
- Always use secure, randomly generated values for `JWT_SECRET`
- Change the default admin password immediately after first login
- Use HTTPS in production
- Keep all dependencies up to date

## API Documentation

The API documentation is available at `/api-docs` when running the server.

## License

MIT