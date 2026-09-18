# ConnectSphere

## Social Media Platform

ConnectSphere is a full-stack social media platform developed as **Task 2 - Social Media Platform** for the **CodeAlpha Full Stack Development Internship**.

The platform allows users to create profiles, share posts, interact with other users, and build connections through likes, comments, and follow/unfollow functionality.

## Features

- User Registration and Login
- JWT-based Authentication
- User Profiles
- Create, Edit and Delete Posts
- Like and Unlike Posts
- Add Comments
- Follow and Unfollow Users
- Search Users
- Followers and Following
- Responsive User Interface
- MongoDB Database

## Technologies Used

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Node.js
- Express.js

### Database
- MongoDB Atlas

### Authentication & Security
- JSON Web Token (JWT)
- bcryptjs
- Helmet
- Express Rate Limit
- CORS

## Project Structure

```text
ConnectSphere/
│
├── backend/
│   ├── server.js
│   ├── User.js
│   ├── Post.js
│   ├── package.json
│   ├── package-lock.json
│   ├── .env
│   └── .gitignore
│
└── frontend/
    ├── index.html
    ├── login.html
    ├── register.html
    └── profile.html