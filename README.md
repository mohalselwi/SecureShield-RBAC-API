 SecureShield — RBAC API
Mini Project II — A Role-Based Access Control (RBAC) API

---

## 👥 Team Members

| Name | ID |
|------|-----|
| Omer Suliman | 210208990 |
| Mohammed Alselwi | 230208817 |

---

 About The Project

**SecureShield** is a secure Role-Based Access Control (RBAC) API built with **Flask** and **Flask-Bcrypt**. It provides authentication and authorization mechanisms with industry-standard security practices.

### Key Security Features:
- ✅ **Salted Password Hashing** using Bcrypt (prevents rainbow-table attacks)
- ✅ **Secure JWT Handling** (no sensitive data stored in payloads)
- ✅ **Role-Based Access Control** (RBAC)
- ✅ **Stateless Authentication**

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| Python 3.x | Backend language |
| Flask | Web framework |
| Flask-Bcrypt | Password hashing |
| PyJWT | Token generation & verification |
| SQLite | Database (development) |

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Steps

1. **Clone the repository**
```bash
git clone https://github.com/mohalselwi/SecureShield-RBAC-API.git
cd SecureShield-RBAC-API
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python app.py
```

4. **Test the API**
```bash
./demo.sh
```

## 📁 Project Structure

```
SecureShield-RBAC-API/
├── app.py              # Main application entry point
├── requirements.txt    # Python dependencies
├── secureshield.db     # SQLite database
├── demo.sh            # Demo script
├── report.docx        # Project report
├── security.log       # Log file
└── .gitignore         # Git ignore rules
```

## 🔐 Security Highlights

### Why Salting?
> Without salt, rainbow tables can crack stolen password hashes instantly. SecureShield uses **Bcrypt** with unique per-user salt (128-bit) and configurable work factor (12 rounds).

### JWT Best Practice
> The API **never stores sensitive data** (passwords, PII) inside JWT payloads. Tokens are signed only, not encrypted — so payload remains readable by anyone who obtains the token.


## 📄 License

This project is for educational purposes as part of **Mini Project II**.

**⭐ Star this repository if you found it useful!**
