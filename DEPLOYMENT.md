# SentinelX Deployment Guide

SentinelX is designed to be cloud-agnostic. Because it is fully Dockerized, you can deploy it to **AWS, Azure, GCP, Render, Railway, Vercel, or DigitalOcean** with ease.

## 1. Environment Variables

The most important configuration is ensuring the Frontend knows where the Backend is located.
When deploying the **Frontend**, you MUST set the following environment variable:
`NEXT_PUBLIC_API_URL=https://your-backend-url.com`

*(Currently, the frontend uses `http://localhost:8000` by default. Before a production build, you should replace the hardcoded `localhost:8000` in the frontend `fetch` calls to use `process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"`)*.

---

## 2. Deployment Strategies

### Option A: PaaS (Vercel + Render/Railway) - *Recommended for FYP*
This is the easiest and fastest way to deploy for a demonstration.

1. **Backend (Render / Railway)**
   - Connect your GitHub repository to [Render](https://render.com) or [Railway](https://railway.app).
   - Point the root directory to `backend/`.
   - The platform will automatically detect the `Dockerfile` and build it.
   - It will give you a public URL (e.g., `https://sentinelx-api.onrender.com`).
   - *(Note on SQLite: On Render/Railway, the local SQLite database will be wiped on every deployment. For an FYP demo, this is usually acceptable since the `seed.py` and `on_startup` hooks automatically regenerate the mock data! If you need persistence, swap the SQLite connection string in `backend/app/database.py` to a managed PostgreSQL database like Neon or Supabase).*

2. **Frontend (Vercel)**
   - Connect your GitHub repository to [Vercel](https://vercel.com).
   - Set the Framework Preset to **Next.js**.
   - Set the Root Directory to `frontend/`.
   - In Environment Variables, add `NEXT_PUBLIC_API_URL` and set it to your Backend URL (e.g., `https://sentinelx-api.onrender.com`).
   - Click Deploy.

### Option B: VPS / Cloud Instance (AWS EC2, Azure VM, DigitalOcean Droplet)
If you want to run everything on a single virtual machine using Docker Compose.

1. Provision an Ubuntu VM on AWS, Azure, or DigitalOcean.
2. Install Docker and Docker Compose.
3. Clone your repository.
4. Run:
   ```bash
   docker-compose up -d --build
   ```
5. The frontend will be available on port 3000, and the backend on port 8000. Use Nginx to map domain names and add SSL.

### Option C: Managed Containers (AWS ECS, Azure Container Apps, Google Cloud Run)
For enterprise-grade scalability.

1. Push the `frontend/Dockerfile` and `backend/Dockerfile` to a container registry (AWS ECR, DockerHub, or GitHub Packages).
2. Deploy the backend image to AWS ECS Fargate or Google Cloud Run.
3. Deploy the frontend image, passing the backend URL as a build argument (`NEXT_PUBLIC_API_URL`).
