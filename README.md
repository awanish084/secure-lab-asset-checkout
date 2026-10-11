# Secure Lab Asset Checkout System

A role-based web application built using **Python, Streamlit, and MySQL** to manage laboratory assets, track checkouts and returns, identify overdue items, and maintain an audit trail.

This project was developed as part of a Secure Application Development mini-project, focusing on CRUD operations, validation, database transactions, and application security.

## Features

- User registration and authentication
- Role-based access for Borrowers and Coordinators
- Laboratory asset search and availability tracking
- Asset checkout and return with due-date tracking
- Overdue checkout identification and CSV export
- Coordinator dashboard with analytics
- Audit logging for selected application activities
- MySQL database for persistent data storage
- Password hashing and parameterized SQL queries

## Technology Stack

- **Language:** Python
- **Frontend:** Streamlit
- **Database:** MySQL
- **Database Connector:** mysql-connector-python
- **Data Processing:** Pandas

## Project Structure

```text
secure-lab-asset-checkout/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
└── .streamlit/
    └── secrets.toml.example
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/secure-lab-asset-checkout.git
cd secure-lab-asset-checkout
```

Alternatively, download the repository as a ZIP file and extract it.

### 2. Create a virtual environment

For Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure MySQL

Start your MySQL server and create the database:

```sql
CREATE DATABASE secure_lab_assets;
```

Configure your database credentials and required application secrets in `.streamlit/secrets.toml`, following the configuration keys expected by `app.py`.

Example configuration:

```toml
[mysql]
host = "localhost"
port = 3306
database = "secure_lab_assets"
user = "YOUR_MYSQL_USER"
password = "YOUR_MYSQL_PASSWORD"

[security]
coordinator_registration_key = "REPLACE_WITH_A_LONG_RANDOM_SECRET"

[app]
demo_seed_enabled = false
```

**Important:** Confirm that these sections and key names match your version of `app.py`. Never upload your real `secrets.toml` file, database password, or secret keys to GitHub.

### 5. Run the application

```bash
streamlit run app.py
```

Open the local URL displayed in your terminal, usually:

```text
http://localhost:8501
```

## Security Measures

The project demonstrates several secure-development practices:

- **Password hashing:** PBKDF2-HMAC-SHA256 with per-password random salts.
- **Constant-time comparison:** `secrets.compare_digest` for password verification.
- **SQL injection protection:** Parameterized SQL queries.
- **Database consistency:** MySQL transactions and row locking during checkout operations.
- **Role-based authorization:** Restrictions on borrower and coordinator actions.
- **Referential integrity:** Database foreign-key constraints.
- **Audit logging:** Recording selected application activities.
- **Secret management:** Keeping database credentials outside the source code.

These measures demonstrate security concepts but do not guarantee production-level security.

## Testing Checklist

- [ ] User registration and login
- [ ] Invalid password rejection
- [ ] Asset search and availability
- [ ] Successful checkout and return
- [ ] Prevention of duplicate or conflicting checkouts
- [ ] Borrower and coordinator authorization checks
- [ ] Overdue identification and CSV export
- [ ] Invalid input handling
- [ ] Audit log verification
- [ ] Database transaction and error-handling checks

Mark a test as complete only after verifying its result.

## Known Limitations

- Concurrent checkout quota checks may need stronger transaction-level protection.
- Application-level audit logs are not necessarily tamper-proof.
- Password policies, account lockout, and session management may need improvement.
- Production deployment requires HTTPS/TLS, secure configuration, and carefully restricted database permissions.
- The project has not been independently security-audited.

This project is intended for educational and demonstration purposes.

## Future Improvements

- Add automated unit and integration tests.
- Strengthen authentication and session management.
- Improve audit-log integrity.
- Add more advanced inventory management.
- Improve concurrency handling for simultaneous checkout requests.
- Deploy using HTTPS and production-grade configuration.

## Author

**Awanish Sharma**
B.Tech Computer Science and Engineering

- GitHub: https://github.com/awanish084
- LinkedIn: https://www.linkedin.com/in/awanishsharma1402

---

Developed as a learning project to explore secure application development using Python, Streamlit, and MySQL.