# UserOperation-NestJS-GraphQL-Microservices

## Overview

This backend project enables user operations such as registration, activation, login, and password management. Built using Node.js, NestJS framework, TypeScript, Prisma, and Apollo Federation 2, it follows a professional file structure and employs microservices architecture within a monorepo setup. NodeMailer is used for user activation and password reset functionalities, while Prisma simplifies database operations. TypeScript enhances type safety throughout the project.

## Technologies Used

- **Node.js**
- **NestJS**
- **TypeScript**
- **Prisma**
- **Apollo Federation 2 (GraphQL)**
- **NodeMailer**

## Features

- User Registration
- User Activation
- User Login
- Fetch Logged-In User Information
- Forgot Password
- Reset Password

## Project Structure

The project follows a professional file structure and is organized as a monorepo, using microservices to handle different aspects of user operations.

## Prerequisites

- Node.js
- NPM
- Git

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/Vikrantsingh22/UserOperation-NestJS-GraphQL-microservices.git
```

### 2. Navigate to the Project Directory

```bash
cd UserOperation-NestJS-GraphQL-microservices
```

### 3. Navigate to the Servers Directory

```bash
cd servers
```

### 4. Install Dependencies

```bash
npm install
```

### 5. Set Up Environment Variables

Create a `.env` file inside the `server` folder and follow the `.env.sample` for reference.

### 6. Start the User Microservice

```bash
npm run start:dev users
```

## GraphQL Requests

### GraphQL Endpoint

```
http://localhost:3001/graphql
```

### Register User

**Request:**

```graphql
mutation Register {
  register(
    registerDto: {
      name: "Vikrant"
      email: "vikrantsingh2288@gmail.com"
      password: "123456789"
      phone_number: 4784515685
    }
  ) {
    activation_token
  }
}
```

**Response:**

```json
{
  "data": {
    "register": {
      "activation_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
  }
}
```

### Activate User

**Request:**

```graphql
mutation ActivateUser {
  activateUser(
    activationInput: {
      activationToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
      activationCode: "4099"
    }
  ) {
    user {
      name
      email
      phone_number
      password
    }
    error {
      message
    }
  }
}
```

**Response:**

```json
{
  "data": {
    "activateUser": {
      "user": {
        "name": "Vikrant",
        "email": "vikrantsingh2288@gmail.com",
        "phone_number": 4784515685,
        "password": "$2b$10$S9T6qx6dI5QA5MMgLURVlOb2DfpBp..."
      },
      "error": null
    }
  }
}
```

### Login User

**Request:**

```graphql
mutation Login {
  Login(email: "vikrantsingh2288@gmail.com", password: "123456789") {
    user {
      id
      name
      password
      phone_number
    }
    accessToken
    refreshToken
    error {
      message
    }
  }
}
```

**Response:**

```json
{
  "data": {
    "Login": {
      "user": {
        "id": "666e9b4df28cdaad947fffab",
        "name": "Vikrant",
        "password": "$2b$10$S9T6qx6dI5QA5MMgLURVlOb2DfpBp...",
        "phone_number": 4784515685
      },
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "error": null
    }
  }
}
```

### Get Logged-In User

**Request:**

```graphql
query GetLoggedInuser {
  getLoggedInuser {
    user {
      id
      name
      email
    }
    accessToken
    refreshToken
  }
}
```

**HTTP Headers:**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**

```json
{
  "data": {
    "getLoggedInuser": {
      "user": {
        "id": "666e9b4df28cdaad947fffab",
        "name": "Vikrant",
        "email": "vikrantsingh2288@gmail.com"
      },
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
  }
}
```

### Forgot Password

**Request:**

```graphql
query ForgotPassword {
  forgotPassword(forgotPasswordDto: { email: "vikrantsingh2288@gmail.com" }) {
    message
  }
}
```

**Response:**

```json
{
  "data": {
    "forgotPassword": {
      "message": "The request is served successfully"
    }
  }
}
```

### Reset Password

**Request:**

```graphql
query ResetPassword {
  resetPassword(
    resetPasswordDto: {
      activationToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
      password: "newPassword"
    }
  ) {
    user {
      email
      phone_number
      password
      name
    }
  }
}
```

**Response:**

```json
{
  "data": {
    "resetPassword": {
      "user": {
        "email": "vikrantsingh2288@gmail.com",
        "phone_number": 4784515685,
        "password": "$2b$10$FtF7RE4TRbA/k9Cv94S5sOYb0QvWIwlUOFXOIv...",
        "name": "Vikrant"
      }
    }
  }
}
```
