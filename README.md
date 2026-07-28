# HealthTrack API

A secure patient records API built with FastAPI, SQLModel, PostgreSQL, JWT authentication, and password hashing.

## Features

* User registration
* User login with JWT
* Password hashing with bcrypt
* Protected endpoints
* Role-based access control (patient, doctor, admin)
* Password reset flow

## Run the project

### Start PostgreSQL

```bash
docker compose up -d
```

### Run the API

```bash
uv run uvicorn main:app --reload
```

### Open Swagger UI

Visit: http://127.0.0.1:8000/docs

## Authentication

Use the **/login** endpoint, then click **Authorize** in Swagger UI and paste the returned bearer token.

## Main Endpoints

* POST /register
* POST /login
* POST /logout
* GET /users/me
* PUT /users/me
* GET /users
* GET /patients
* GET /patients/{patient_id}
* POST /forgot-password
* POST /reset-password
