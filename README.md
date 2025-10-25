# Postly - Blog Application

A full-stack blog application built with **FastAPI** (backend) and **React with custom CSS** (frontend). Users can register, log in, create/edit/delete posts, and view all posts.

## Features
- User authentication (JWT-based)
- CRUD operations for blog posts
- Minimal, responsive UI with custom CSS
- SQLite database with SQLAlchemy
- Secure password hashing with bcrypt

## Tech Stack
- **Backend**: FastAPI, SQLAlchemy, SQLite, python-jose, passlib
- **Frontend**: React, Custom CSS, Axios, react-router-dom
- **Deployment**: Render (backend), Vercel (frontend)

## Deployment
- Backend: [https://your-backend.onrender.com](https://your-backend.onrender.com)
- Frontend: [https://your-frontend.vercel.app](https://your-frontend.vercel.app)

## Screenshots
![Home Page](screenshots/home.png)
![Login Page](screenshots/login.png)

## Setup
### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
