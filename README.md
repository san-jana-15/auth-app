Register User

URL: /api/auth/register
Method: POST
Description: Registers a new user.

Request Body (JSON):
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "password123"
}

Response (Success):

{
  "message": "User registered successfully"
}

Response (Error - Duplicate Email or Server Error):

{
  "error": "Email already exists"
}

or

{
  "error": "Internal server error message"
}

Notes:
Password is hashed using bcrypt before saving.
Email should be unique.

Login User

URL: /api/auth/login
Method: POST
Description: Logs in a user and returns a JWT token.

Request Body (JSON):

{
  "email": "john@example.com",
  "password": "password123"
}


Response (Success):

{
  "token": "<JWT_TOKEN>"
}


Response (Error - Invalid Credentials):

{
  "message": "User not found"
}


or

{
  "message": "Invalid credentials"
}


Notes:

The token expires in 1 hour (expiresIn: '1h').

Use this token for accessing protected routes.
Get Current User (Protected Route)

URL: /api/auth/me
Method: GET
Description: Returns the logged-in user's data. Requires JWT authentication.

Headers:

Authorization: Bearer <JWT_TOKEN>


Response (Success):

{
  "_id": "652b1b0a0f1e2c0012abcd34",
  "username": "john_doe",
  "email": "john@example.com",
  "createdAt": "2025-10-21T09:25:30.000Z",
  "updatedAt": "2025-10-21T09:25:30.000Z"
}


Response (Error - Missing Token):

{
  "message": "Access denied"
}


Response (Error - Invalid Token):

{
  "message": "Invalid token"
}

Testing with Postman

Register a new user

Method: POST

URL: http://localhost:5000/api/auth/register

Body: JSON → username, email, password

Login the user

Method: POST

URL: http://localhost:5000/api/auth/login

Body: JSON → email, password

Copy the returned token

Get current user

Method: GET

URL: http://localhost:5000/api/auth/me

Headers → Authorization: Bearer <JWT_TOKEN>

Tip: Use Postman’s “Environment Variables” to store the JWT token for easy reuse.

Additional Notes

Passwords are never returned in responses.

Always store your JWT secret securely and do not expose it publicly.

Consider adding email validation, password strength checks, and refresh tokens for a production-ready system.

Enable CORS if your frontend is hosted on a different origin:

import cors from 'cors';
app.use(cors());