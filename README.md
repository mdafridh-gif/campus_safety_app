# Campus Safety — Response Center

A responsive campus safety prototype with a student SOS flow, an administrator dashboard, authenticated API endpoints, incident timeline, role checks, and local SQLite persistence. `schema.sql` is the PostgreSQL production data model; media bytes are kept outside the relational database.

## Run locally

Requires Python 3.10 or newer. The application uses only the Python standard library.

```powershell
py server.py
```

Open <http://localhost:8000>. The application creates `campus_safety.db` on first run, seeds a database-backed administrator account and the configured emergency contacts, and starts with no sample incidents or student accounts. Student incidents and authentication activity are stored in the database.

There are two account roles: students and administrators. Students use separate **Student login** and **Student register** screens; administrators use **Admin login** only. Registration collects name, register number, department, phone number, year of study, email, and password. Register numbers and email addresses must be unique. Accounts are stored in SQLite, and passwords are stored as PBKDF2 hashes.

Local demo administrator account (password: `CampusSafe2026!`):

| Role | Email |
| --- | --- |
| Administrator | `admin@campus.edu` |

Configure the primary call line with `SOS_PHONE=8531996611`. Tapping SOS opens the device phone app with the campus number and creates the incident and call-workflow record. The phone app or operating system may require the student to confirm the call; placing calls without that confirmation requires a campus telephony provider.

## Included flows

- Student SOS creates the incident before requesting optional location, and reports success only after the API confirms receipt.
- Sending an SOS requests camera and microphone permission and, if both are granted, records audio and video for up to 60 seconds and captures one photo. Audio, video, and photo entries appear in incident evidence as soon as capture begins; uploads then update those same entries. A persistent on-screen indicator and stop control remain visible during capture; denying permission never blocks the emergency alert.
- Campus alerts and a call-workflow record are created with the incident; staff views refresh every 15 seconds.
- Students can share geolocation after the browser permission prompt, cancel an eligible alert, add a note, manually record audio, and upload photo, video, or audio evidence.
- Evidence is stored under a private local directory, with metadata and checksums in SQLite. Downloads require an authenticated request and incident authorization.
- Administrators can acknowledge, assign responders, mark responding, record arrival, resolve with notes, filter incidents, and inspect timelines, notifications, calls, and analytics.
- Login is rate limited, sessions expire after eight hours, role access is checked on API routes, user input is bounded, and student incident access is scoped to the reporting student.
- Student/admin accounts are read from SQLite, successful sign-ins update `last_login_at`, and sign-in/sign-out events are recorded in the audit history. SOS requests include a unique client request ID so network retries do not create duplicate incidents.
- GPS fixes include numeric coordinates and reported accuracy. Incident details offer an exact-coordinate pin link to Google Maps.

## API overview

`POST /api/auth/login`, `GET /api/me`, `POST /api/incidents`, `GET /api/incidents`, `GET /api/incidents/{id}`, `POST /api/incidents/{id}/acknowledge`, `/assign`, `/respond`, `/arrive`, `/resolve`, `/cancel`, `/location`, `/evidence`, `GET /api/evidence/{id}`, `GET /api/notifications`, `GET /api/admin/dashboard`, and `GET /api/admin/reports`.

The current file receiver accepts evidence up to 15 MB per request. Local evidence is private to the filesystem and download endpoints check the current session and incident membership. Set `CAMPUS_PRIVATE_STORAGE` to a protected volume in local deployments.

## Production integration work

This runnable build is a prototype foundation, not a deployable emergency service. Before a campus uses it with real incidents, replace the demo identity store and shared demo password with institutional SSO or a maintained identity provider; move from in-memory sessions to revocable server-side sessions; deploy behind HTTPS; replace SQLite with PostgreSQL using `schema.sql`; use private S3-compatible object storage and short-lived signed downloads; and add durable asynchronous queues plus a campus-approved push/SMS/email and telephony provider. Configure monitoring, backups, retention/deletion jobs, incident response procedures, and jurisdiction-specific privacy/legal review. The built-in call row is a workflow record and does not itself dial the emergency number. No push, SMS, email, external maps, or background mobile behavior is simulated as delivered.

This is a web application, not a native iOS/Android package. Browser location and microphone permissions generally require `localhost` or HTTPS. OS permission prompts and visible recording state are respected; recording is never started without the student pressing the record control and approving microphone access.
