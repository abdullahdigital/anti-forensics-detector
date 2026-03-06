# How to Run the Project

## 1. Start the Backend (Python/Flask)
The backend service runs on `http://localhost:5000`.

**Open a terminal** and run:

```powershell
# Navigate to backend
cd "backend/python"

# Activate the virtual environment
source venv/bin/activate
# Start the server
python main.py
```

## 2. Start the Frontend (Angular)
The frontend UI runs on `http://localhost:4200` (by default).

**Open a NEW terminal** and run:

```powershell
# Navigate to frontend
cd "frontend"

# Start the application
npm start
```
*Note: If port 4200 is busy, it may ask to use a different port (e.g., 4201, 4202). You can accept that.*

---

## Setup (First Time Only)
If you move this project to a new computer, run these setup commands first:

**Backend Setup:**
```powershell
cd "backend/python"
python -m venv venv
.\venv\Scripts\Activate
pip install -r requirements.txt
```

**Frontend Setup:**
```powershell
cd "frontend"
npm install
```
