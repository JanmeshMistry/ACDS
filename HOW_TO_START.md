# How to Start ACDS

## First time setup

```bash
# 1. Create a virtual environment (do this once)
python -m venv venv

# 2. Activate it
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy the example env file and add your API keys
cp .env.example .env
# Then open .env and fill in your VirusTotal and OTX keys

# 5. Create the static folder (fixes Django warning)
mkdir dashboard\static        # Windows
mkdir -p dashboard/static     # Mac/Linux

# 6. Create the logs folder
mkdir logs

# 7. Make sure MongoDB is running
# Windows: open Services and start "MongoDB"
# Linux: sudo systemctl start mongod
```

---

## Running the project (3 terminals)

Open 3 separate terminal windows, activate the venv in each one, then:

**Terminal 1 - Web Honeypot (the fake login page)**
```bash
cd ACDS
python honeypot/web_honeypot.py
```
Visit http://localhost:5000 to see the fake login page.

**Terminal 2 - Dashboard**
```bash
cd ACDS
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```
Visit http://localhost:8000 to see the SOC dashboard.

**Terminal 3 - Generate test data**
```bash
cd ACDS
python tests/simulate_attack.py --web --scan
```
This sends fake attacks so you have data to look at in the dashboard.

---

## Or just run everything at once (1 terminal)

```bash
python main.py --all --no-ssh
```

`--no-ssh` skips the SSH honeypot since it can cause issues on Windows.

---

## Create a Django admin account

Run this once to set up your dashboard admin login:
```bash
python manage.py createsuperuser
```
Then go to http://localhost:8000/admin/ and log in.

---

## Useful URLs

| URL | What it does |
|-----|-------------|
| http://localhost:5000 | Fake login page (honeypot) |
| http://localhost:8000 | SOC dashboard |
| http://localhost:8000/logs/ | All captured events |
| http://localhost:8000/blocked/ | Blocked IP management |
| http://localhost:8000/api/stats/ | Raw JSON stats |
| http://localhost:8000/admin/ | Django admin |

---

## Common problems

**"Cannot connect to MongoDB"**
Start MongoDB first. On Windows, check Services for "MongoDB Server".

**"iptables not found" / firewall blocking doesn't work**
This is normal on Windows - iptables is Linux only.
Everything else still works fine (logging, intel, dashboard).

**Dashboard shows no data**
Run the attack simulator: `python tests/simulate_attack.py --web --scan`

**VirusTotal/OTX scores look random**
You're in mock mode. Add real API keys to your .env file.
Both are free - links are in the .env.example file.
