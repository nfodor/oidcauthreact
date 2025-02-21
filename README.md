
# RBAC with OpenAPI Documentation

This project demonstrates a Role-Based Access Control (RBAC) system with OpenAPI documentation, where users have specific roles (Admin, Editor, Viewer) that determine their access rights to the API endpoints.

## Features

- **RBAC**: Users can have roles such as Admin, Editor, or Viewer, and their permissions are enforced using middleware.
- **OpenAPI Documentation**: The project includes automatically generated OpenAPI documentation using `swagger-jsdoc` and `swagger-ui-express`, available at `/api-docs`.
- **Content CRUD Operations**: Admin and Editor roles can create and edit content, while Viewers can only view content.

## Getting Started

### Prerequisites

You need to have **Node.js** and **npm** installed. You can install them from [here](https://nodejs.org/).

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repository/rbac-openapi-project.git
   cd rbac-openapi-project
   ```

2. Install the dependencies:
   ```bash
   npm install
   ```

3. Set up a `.env` file in the root of the project with the following:
   ```bash
   JWT_SECRET=your_secret_key
   EMAIL_USER=your_email_address
   EMAIL_PASSWORD=your_email_password
   ```

4. Start the server:
   ```bash
   npm run dev
   ```

5. Access the OpenAPI documentation at `http://localhost:5000/api-docs`.

### Running the Project

- Run the backend with:
  ```bash
  npm start
  ```
- To generate the OpenAPI documentation, run:
  ```bash
  npm run docs
  ```

## API Endpoints

### Content Endpoints

- `POST /content`: Create content (Admin, Editor).
- `PUT /content/{id}`: Edit content (Admin, Editor).
- `GET /content/{id}`: View content (Admin, Editor, Viewer).
- `DELETE /content/{id}`: Delete content (Admin).

### User Management (Admin Only)

- `GET /admin/users`: View all users (Admin).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
    