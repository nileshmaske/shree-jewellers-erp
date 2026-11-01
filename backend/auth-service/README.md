# Auth Service — Module 1

Java 21, Spring Boot 3.4.5, Gradle, Spring Security, JWT (HS256 development starter), MySQL 8 and Flyway.

## Local startup
1. Create MySQL database: `CREATE DATABASE auth_db;`
2. Export `DB_USERNAME`, `DB_PASSWORD` and a cryptographically random `JWT_SECRET` (at least 32 bytes).
3. Run `gradle bootRun` from this folder. Generate and commit the Gradle wrapper before CI/CD.
4. Use `POST /api/auth/login` with a provisioned user and password.
5. Use `Authorization: Bearer <token>` for `GET /api/auth/me`.

## Security limitations / next steps
- No default admin credentials are seeded. Provision accounts securely in a dedicated bootstrap/admin flow.
- This starter uses a shared HS256 secret; for EKS production switch to asymmetric signing and JWKS verification, with keys managed using AWS Secrets Manager/KMS.
- Implement refresh token rotation, logout revocation, audit logging, rate limits, lockout, and integration tests before production.
- Docker image expects a prebuilt jar (`gradle bootJar`).
- EKS manifests, ECR push and RDS connectivity will follow after local verification.
