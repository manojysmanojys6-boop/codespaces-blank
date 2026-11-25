# Emergency SOS Backend

Python + FastAPI + SQLite backend for the uploaded Emergency SOS frontend.

## 1. Run locally

```bash
# Windows
py -m venv .venv
.venv\Scripts\activate

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:
- API: http://127.0.0.1:8000
- Interactive API documentation: http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/api/health

SQLite database is created automatically as `emergency_sos.db`.

## 2. Main endpoints

| Method | Endpoint | Login required | Purpose |
|---|---|---:|---|
| GET | `/api/health` | No | Check backend |
| POST | `/api/auth/register` | No | Create account |
| POST | `/api/auth/login` | No | Login and receive token |
| POST | `/api/auth/logout` | Yes | End current session |
| GET | `/api/me` | Yes | Current account |
| GET | `/api/contacts` | Yes | List emergency contacts |
| POST | `/api/contacts` | Yes | Add a contact |
| PUT | `/api/contacts/{id}` | Yes | Update a contact |
| DELETE | `/api/contacts/{id}` | Yes | Delete a contact |
| POST | `/api/sos` | Yes | Record an SOS event and optional GPS coordinates |
| GET | `/api/sos/history` | Yes | View recent SOS events |

## 3. Example requests

Register:
```json
{
  "name": "Demo User",
  "email": "demo@example.com",
  "password": "ChangeThis123"
}
```

Login:
```json
{
  "email": "demo@example.com",
  "password": "ChangeThis123"
}
```

For all protected endpoints, include the login response token:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Add a contact:
```json
{
  "name": "Family",
  "phone": "+919876543210"
}
```

Create an SOS event:
```json
{
  "latitude": 12.9716,
  "longitude": 77.5946,
  "accuracy_m": 15,
  "message": "I need emergency help"
}
```

## 4. Important safety and deployment notes

- This backend records an SOS event. It does **not** call police/ambulance, send SMS, or guarantee that anyone receives an alert.
- The frontend's `tel:` links still initiate calls from the user's phone. Verify the correct emergency number for the user's country; do not rely on a region dropdown as a substitute for local emergency guidance.
- Browser GPS usually requires HTTPS (or localhost) and the user's permission.
- Before public deployment: set `CORS_ORIGINS` to your exact frontend origin, use HTTPS, use a persistent disk/database, configure backups, add rate limiting and monitoring, and review privacy/retention requirements for location data.
- Do not commit real secrets or personal emergency-contact data to Git.
- This starter uses SQLite for simple development. For a larger public service, use managed PostgreSQL and stronger operational controls.
