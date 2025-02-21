# RBAC OpenAPI Project

A Role-Based Access Control (RBAC) project with OpenAPI specification, featuring both server and client implementations.

## Features

- User authentication with JWT
- Role-based access control (Admin, Editor, User roles)
- Content management with role-based permissions
- API documentation with OpenAPI/Swagger
- Comprehensive test suite

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MongoDB
- npm or yarn

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd RBAC-OpenAPI-Project
```

2. Install dependencies for both server and client:
```bash
# Install server dependencies
cd server
npm install

# Install client dependencies
cd ../client
npm install
```

3. Set up environment variables:
```bash
# Server environment variables
cd server
cp .env.example .env
# Edit .env with your configuration

# Client environment variables
cd ../client
cp .env.example .env
# Edit .env with your configuration
```

### Running the Application

1. Start the server:
```bash
cd server
npm run dev
```

2. Start the client:
```bash
cd client
npm start
```

### Running Tests

```bash
cd server
npm test
```

## Development

### Making Changes

1. Create a new branch:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes and run tests:
```bash
cd server
npm test
```

3. Commit your changes with a descriptive message:
```bash
git add .
git commit -m "feat: description of your changes"
```

4. Push to your branch:
```bash
git push origin feature/your-feature-name
```

### Commit Message Guidelines

Follow the conventional commits specification:

- `feat:` - A new feature
- `fix:` - A bug fix
- `docs:` - Documentation changes
- `test:` - Adding or modifying tests
- `refactor:` - Code changes that neither fix a bug nor add a feature

Example:
```bash
git commit -m "feat: add user role update endpoint"
git commit -m "test: add test suite for content management"
```

## API Documentation

The API documentation is available at `/api-docs` when running the server.

## License

This project is licensed under the MIT License - see the LICENSE file for details.