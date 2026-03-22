CyberRecon Web Reconnaissance Platform

CyberRecon is a production ready full stack reconnaissance platform built with FastAPI, Next.js, PostgreSQL, and cloud deployment infrastructure. The project demonstrates asynchronous scanning workflows, backend API orchestration, frontend polling systems, persistent scan history storage, and real world deployment practices.


Live Deployment

Frontend Dashboard
https://cyberrecon.vercel.app

Backend API Documentation
https://cyberrecon-jriu.onrender.com/docs

Overview

CyberRecon was designed to simulate a real world reconnaissance workflow similar to the early stages of professional security assessments and bug bounty pipelines. The platform accepts a target domain and performs automated intelligence gathering including DNS enumeration, WHOIS lookup, IP intelligence, open port detection, subdomain discovery, and technology fingerprinting. It demonstrates backend API architecture, asynchronous job tracking, frontend polling logic, environment based configuration, and production cloud deployment integration. This project showcases both application development and infrastructure deployment skills rather than only local scripting or single layer tools.

Features

Domain intelligence summary
DNS record extraction
WHOIS lookup
Subdomain enumeration
Open port detection
Technology fingerprinting
Asynchronous scan execution
Job based polling system
Persistent scan history storage
Local and database backed history recovery
Environment based deployment configuration
Frontend and backend separation
Production deployment on Vercel and Render

Architecture

Client requests are handled by a Next.js frontend application.
The frontend submits scan jobs to a FastAPI backend service.
The backend performs reconnaissance tasks asynchronously and stores results in PostgreSQL.
Scan progress is tracked using job identifiers returned to the frontend.
The frontend polls the backend until results are completed.
Recent scan history is retrieved from both local storage and the backend database.

The backend API is deployed on Render.

The frontend dashboard is deployed on Vercel.

Environment variables control API routing between development and production environments.

Tech Stack

Frontend

Next.js
React
TypeScript
Tailwind CSS

Backend

Python
FastAPI
SQLAlchemy
Uvicorn

Database

Supabase

Cloud and Deployment

Render
Vercel

Dev Tools

Environment variables
REST API architecture
Asynchronous polling workflows

Security Concepts Demonstrated

Environment variable configuration
Backend service separation from frontend UI
Controlled API polling architecture
Input validation handling
Cloud based deployment isolation

Local Development Setup

Clone the repository

git clone https://github.com/Learnlife001/cyberrecon.git
cd cyberrecon

Start backend server

cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn api_server:app --reload

Start frontend server

cd frontend
npm install
npm run dev

Configure environment variables

Create frontend/.env.local

NEXT_PUBLIC_API_URL=http://localhost:8000

Scan Workflow

User submits target domain

Frontend sends request to

POST /scan

Backend returns job identifier

Frontend polls

GET /results/{job_id}

Until scan completes

Recent scans are retrieved from

GET /scans

Results are rendered dynamically inside dashboard panels

CI and Deployment Workflow

Frontend is deployed automatically through Vercel

Backend is deployed through Render cloud services

Environment variables control API routing between development and production environments

Production deployments are separated from local development environments for stability and reliability

Production Lessons Learned

Environment configuration differences affect frontend backend communication

CORS handling is required for cross origin deployments

Polling architecture improves reliability of asynchronous scan workflows

Database backed scan history enables persistent recon tracking

Cloud deployment separation improves maintainability and debugging

My Future Improvements

Subdomain brute forcing engine integration

HTTP service fingerprinting

Directory enumeration support

Export scan results as JSON or PDF

Scan comparison history

User authentication system

Scan scheduling support

Rate limiting protection

Redis caching layer

Monitoring and alerting integration

Author

Chigozie Okuma

GitHub
https://github.com/Learnlife001
LinkedIn
https://www.linkedin.com/in/cjokuma23/
Portfolio
https://learnlife-portfolio.vercel.app/
