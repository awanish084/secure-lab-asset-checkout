

import datetime
import hashlib
import secrets
from contextlib import contextmanager
from typing import Optional, Tuple

import mysql.connector
import pandas as pd
import streamlit as st
from mysql.connector import Error, errorcode

# ---------------------------------------------------------------------------
# PAGE CONFIGURATION & SECRETS VALIDATION
# ---------------------------------------------------------------------------

st.set_page_config(page_title="Lab Asset Checkout", page_icon="🔬", layout="wide")

if "mysql" not in st.secrets or "security" not in st.secrets:
    st.error(
        "Missing configuration: `.streamlit/secrets.toml` must have "
        "`[mysql]` and `[security]` sections."
    )
    st.stop()

COORDINATOR_SECRET_KEY = str(st.secrets["security"].get("coordinator_secret_key", ""))
if not COORDINATOR_SECRET_KEY:
    st.error("`[security] coordinator_secret_key` must be set to a non-empty value.")
    st.stop()

DEMO_CFG = st.secrets["demo"] if "demo" in st.secrets else {}
DEMO_ENABLED = bool(DEMO_CFG.get("enabled", False))

MAX_ACTIVE_CHECKOUTS = 3
MIN_PASSWORD_LENGTH = 10
PBKDF2_ITERATIONS = 100_000  # changing this invalidates existing hashes

# ---------------------------------------------------------------------------
# GENERAL HELPERS
# ---------------------------------------------------------------------------

def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def fmt(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")

# ---------------------------------------------------------------------------
# CRYPTOGRAPHY & AUTHENTICATION HELPERS
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
    ).hex()
    return hashed, salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)

# ---------------------------------------------------------------------------
# MYSQL CONNECTION HELPERS
# ---------------------------------------------------------------------------

def get_db_connection():
    cfg = st.secrets["mysql"]
    return mysql.connector.connect(
        host=cfg["host"],
        user=cfg["user"],
        password=cfg["password"],
        database=cfg["database"],
        port=int(cfg.get("port", 3306)),
        autocommit=False,
    )

@contextmanager
def db_connection():
    """Yield a connection; always close it (uncommitted work is rolled back)."""
    conn = get_db_connection()
    try:
        yield conn
    finally:
        if conn.is_connected():
            conn.close()

def query_df(sql: str, params: Optional[tuple] = None) -> pd.DataFrame:
    with db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(sql, params or ())
            rows = cursor.fetchall()
            columns = [c[0] for c in cursor.description]
        finally:
            cursor.close()
    return pd.DataFrame(rows, columns=columns)

# ---------------------------------------------------------------------------
# SCHEMA INITIALIZATION
# ---------------------------------------------------------------------------

def seed_demo_accounts(cursor) -> None:
    """Create demo users ONLY when explicitly enabled in secrets.toml."""
    coord_pw = str(DEMO_CFG.get("coordinator_password", ""))
    borrower_pw = str(DEMO_CFG.get("borrower_password", ""))
    if len(coord_pw) < MIN_PASSWORD_LENGTH or len(borrower_pw) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            "Demo mode is enabled but [demo] coordinator_password / borrower_password "
            f"are missing or shorter than {MIN_PASSWORD_LENGTH} characters."
        )
    now = fmt(utc_now())
    for username, pw, name, role in [
        ("coord_admin", coord_pw, "Demo Coordinator", "coordinator"),
        ("student_101", borrower_pw, "Demo Borrower", "borrower"),
    ]:
        h, s = hash_password(pw)
        cursor.execute(
            """INSERT IGNORE INTO users
               (username, password_hash, salt, full_name, role, created_at)
               VALUES (%s, %s, %s, %s, %s, %s);""",
            (username, h, s, name, role, now),
        )

@st.cache_resource(show_spinner=False)
def initialize_database() -> bool:
    """Create schema once per process. Returns True on success."""
    try:
        with db_connection() as conn:
            cursor = conn.cursor(dictionary=True, buffered=True)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username VARCHAR(64) PRIMARY KEY,
                    password_hash VARCHAR(128) NOT NULL,
                    salt VARCHAR(64) NOT NULL,
                    full_name VARCHAR(128) NOT NULL,
                    role ENUM('borrower', 'coordinator') NOT NULL DEFAULT 'borrower',
                    created_at DATETIME NOT NULL
                ) ENGINE=InnoDB;
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id VARCHAR(64) PRIMARY KEY,
                    name VARCHAR(128) NOT NULL,
                    category VARCHAR(64) NOT NULL,
                    status ENUM('AVAILABLE', 'CHECKED_OUT', 'MAINTENANCE')
                        NOT NULL DEFAULT 'AVAILABLE'
                ) ENGINE=InnoDB;
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS checkouts (
                    checkout_id INT AUTO_INCREMENT PRIMARY KEY,
                    asset_id VARCHAR(64) NOT NULL,
                    borrower_id VARCHAR(64) NOT NULL,
                    checkout_date DATETIME NOT NULL,
                    due_date DATETIME NOT NULL,
                    returned_date DATETIME NULL,
                    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE RESTRICT,
                    FOREIGN KEY (borrower_id) REFERENCES users(username) ON DELETE RESTRICT
                ) ENGINE=InnoDB;
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    log_id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    actor_id VARCHAR(64) NOT NULL,
                    role VARCHAR(32) NOT NULL,
                    event_type VARCHAR(64) NOT NULL,
                    target_asset_id VARCHAR(64) NULL,
                    details TEXT NOT NULL
                ) ENGINE=InnoDB;
            """)

            if DEMO_ENABLED:
                seed_demo_accounts(cursor)

                       # Sample inventory (non-sensitive) is seeded only when demo mode is on.
            asset_count = 0
            if DEMO_ENABLED:
                cursor.execute("SELECT COUNT(*) AS count FROM assets;")
                asset_count = cursor.fetchone()["count"]
            if DEMO_ENABLED and asset_count == 0:
                cursor.executemany(
                    "INSERT INTO assets (asset_id, name, category, status) VALUES (%s, %s, %s, %s);",
                    [
                        ("OSC-101", "Digital Oscilloscope 100MHz", "Electronics", "AVAILABLE"),
                        ("OSC-102", "Digital Oscilloscope 200MHz", "Electronics", "AVAILABLE"),
                        ("RPI-201", "Raspberry Pi 4 8GB Kit", "Computing", "AVAILABLE"),
                        ("RPI-202", "Raspberry Pi 4 4GB Kit", "Computing", "AVAILABLE"),
                        ("DMM-301", "Fluke Digital Multimeter", "Electronics", "MAINTENANCE"),
                        ("SOL-401", "Soldering Station 60W", "Fabrication", "AVAILABLE"),
                    ],
                )

            conn.commit()
            cursor.close()
        return True
    except (Error, ValueError) as e:
        st.error(f"Database initialization error: {e}")
        return False

# ---------------------------------------------------------------------------
# AUDIT LOGGING
# ---------------------------------------------------------------------------

def write_audit_log(actor_id: str, role: str, event_type: str, details: str,
                    asset_id: Optional[str] = None) -> None:
    """Uses its own connection so it never joins (or blocks on) a caller's transaction."""
    try:
        with db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO audit_logs
                   (timestamp, actor_id, role, event_type, target_asset_id, details)
                   VALUES (%s, %s, %s, %s, %s, %s);""",
                (fmt(utc_now()), actor_id, role, event_type, asset_id, details),
            )
            conn.commit()
            cursor.close()
    except Error as e:
        print(f"Audit log write failed: {e}")

# ---------------------------------------------------------------------------
# AUTHENTICATION
# ---------------------------------------------------------------------------

def register_user(username: str, password: str, full_name: str, role: str,
                  secret_key: str = "") -> Tuple[bool, str]:
    username = username.strip().lower()
    full_name = full_name.strip()

    if len(username) < 3 or not username.isalnum():
        return False, "Username must be alphanumeric and at least 3 characters long."
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if not full_name:
        return False, "Full name is required."
    if role not in ("borrower", "coordinator"):
        return False, "Invalid role."
    if role == "coordinator" and not secrets.compare_digest(
        secret_key.encode("utf-8"), COORDINATOR_SECRET_KEY.encode("utf-8")
    ):
        write_audit_log(username, "anonymous", "AUTH_FAILURE",
                        "Failed coordinator secret key during signup")
        return False, "Invalid Coordinator authorization registration key."

    pwd_hash, salt = hash_password(password)
    try:
        with db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """INSERT INTO users
                       (username, password_hash, salt, full_name, role, created_at)
                       VALUES (%s, %s, %s, %s, %s, %s);""",
                    (username, pwd_hash, salt, full_name, role, fmt(utc_now())),
                )
                conn.commit()
            except Error as e:
                conn.rollback()
                if e.errno == errorcode.ER_DUP_ENTRY:
                    return False, f"Username '{username}' already exists."
                raise
            finally:
                cursor.close()
        write_audit_log(username, role, "USER_REGISTERED", f"Account created for {full_name}")
        return True, "Registration successful! You may now log in."
    except Error as e:
        return False, f"Database error: {e}"

def authenticate_user(username: str, password: str) -> Tuple[bool, Optional[dict], str]:
    username = username.strip().lower()
    try:
        with db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s;", (username,))
            user = cursor.fetchone()
            cursor.close()

        if not user:
            write_audit_log(username, "anonymous", "LOGIN_FAILED", "User does not exist")
            return False, None, "Invalid username or password."
        if not verify_password(password, user["password_hash"], user["salt"]):
            write_audit_log(username, user["role"], "LOGIN_FAILED", "Incorrect password")
            return False, None, "Invalid username or password."

        write_audit_log(username, user["role"], "LOGIN_SUCCESS", "User authenticated successfully")
        return True, user, "Login successful."
    except Error as e:
        return False, None, f"Database error: {e}"

# ---------------------------------------------------------------------------
# CORE BUSINESS LOGIC
# ---------------------------------------------------------------------------

def perform_checkout(actor_id: str, role: str, asset_id: str,
                     duration_days: int) -> Tuple[bool, str]:
    if duration_days <= 0 or duration_days > 30:
        msg = f"Invalid loan duration: {duration_days} days. Must be between 1 and 30 days."
        write_audit_log(actor_id, role, "VALIDATION_FAILED", msg, asset_id)
        return False, msg

    def reject(conn, message: str, event: str = "VALIDATION_FAILED") -> Tuple[bool, str]:
        conn.rollback()  # release locks before logging
        write_audit_log(actor_id, role, event, message, asset_id)
        return False, message

    try:
        with db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                # Lock order is always: borrower row -> asset row (prevents deadlocks).

                # 1. Lock the borrower's row. This serializes concurrent checkouts by
                #    the same borrower, so the quota check below cannot be raced.
                cursor.execute(
                    "SELECT username FROM users WHERE username = %s FOR UPDATE;",
                    (actor_id,),
                )
                if not cursor.fetchone():
                    return reject(conn, f"Borrower '{actor_id}' does not exist.")

                # 2. Quota check (locking read = current read, sees committed loans).
                cursor.execute(
                    """SELECT COUNT(*) AS count FROM checkouts
                       WHERE borrower_id = %s AND returned_date IS NULL FOR UPDATE;""",
                    (actor_id,),
                )
                active_loans = cursor.fetchone()["count"]
                if active_loans >= MAX_ACTIVE_CHECKOUTS:
                    return reject(
                        conn,
                        f"Checkout quota exceeded. Borrower holds "
                        f"{active_loans}/{MAX_ACTIVE_CHECKOUTS} items.",
                    )

                # 3. Lock and validate the asset.
                cursor.execute(
                    "SELECT status FROM assets WHERE asset_id = %s FOR UPDATE;",
                    (asset_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return reject(conn, f"Asset '{asset_id}' does not exist.")
                if row["status"] != "AVAILABLE":
                    return reject(
                        conn, f"Asset '{asset_id}' is unavailable (Status: {row['status']})."
                    )

                # 4. Record the checkout.
                now_dt = utc_now()
                due_dt = now_dt + datetime.timedelta(days=duration_days)
                cursor.execute(
                    "UPDATE assets SET status = 'CHECKED_OUT' WHERE asset_id = %s;",
                    (asset_id,),
                )
                cursor.execute(
                    """INSERT INTO checkouts (asset_id, borrower_id, checkout_date, due_date)
                       VALUES (%s, %s, %s, %s);""",
                    (asset_id, actor_id, fmt(now_dt), fmt(due_dt)),
                )
                conn.commit()
            finally:
                cursor.close()

        due_label = due_dt.strftime("%Y-%m-%d")
        write_audit_log(actor_id, role, "CHECKOUT_SUCCESS", f"Due on {due_label}", asset_id)
        return True, f"Checkout confirmed. Due on {due_label}."
    except Error as e:
        msg = f"Database transaction aborted: {e}"
        write_audit_log(actor_id, role, "SYSTEM_ERROR", msg, asset_id)
        return False, msg

def perform_return(actor_id: str, role: str, asset_id: str) -> Tuple[bool, str]:
    try:
        with db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute(
                    """SELECT checkout_id, borrower_id FROM checkouts
                       WHERE asset_id = %s AND returned_date IS NULL FOR UPDATE;""",
                    (asset_id,),
                )
                record = cursor.fetchone()
                if not record:
                    conn.rollback()
                    msg = f"No active loan found for asset '{asset_id}'."
                    write_audit_log(actor_id, role, "VALIDATION_FAILED", msg, asset_id)
                    return False, msg

                if role != "coordinator" and actor_id != record["borrower_id"]:
                    conn.rollback()
                    msg = f"Permission denied: Item was checked out by '{record['borrower_id']}'."
                    write_audit_log(actor_id, role, "AUTH_FAILURE", msg, asset_id)
                    return False, msg

                cursor.execute(
                    "UPDATE assets SET status = 'AVAILABLE' WHERE asset_id = %s;", (asset_id,)
                )
                cursor.execute(
                    "UPDATE checkouts SET returned_date = %s WHERE checkout_id = %s;",
                    (fmt(utc_now()), record["checkout_id"]),
                )
                conn.commit()
            finally:
                cursor.close()

        write_audit_log(actor_id, role, "RETURN_SUCCESS",
                        f"Cleared checkout ID {record['checkout_id']}", asset_id)
        return True, f"Asset '{asset_id}' returned successfully."
    except Error as e:
        msg = f"Database transaction aborted: {e}"
        write_audit_log(actor_id, role, "SYSTEM_ERROR", msg, asset_id)
        return False, msg

# ---------------------------------------------------------------------------
# INITIALIZE & SESSION STATE
# ---------------------------------------------------------------------------

if not initialize_database():
    st.stop()

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.role = None
    st.session_state.full_name = None

# ---------------------------------------------------------------------------
# VIEW: UNAUTHENTICATED (LOGIN / SIGN UP)
# ---------------------------------------------------------------------------

if not st.session_state.authenticated:
    st.title("🔬 Lab Asset Checkout — Portal")

    if DEMO_ENABLED:
        st.warning(
            "Demo mode is enabled: demo accounts exist on this instance. "
            "Disable `[demo] enabled` in secrets.toml for any real deployment."
        )

    auth_tab = st.radio("Choose Action", ["Login", "Sign Up"], horizontal=True)

    if auth_tab == "Login":
        st.subheader("Account Login")
        with st.form("login_form"):
            login_user = st.text_input("Username")
            login_pwd = st.text_input("Password", type="password")
            submit_login = st.form_submit_button("Log In")

        if submit_login:
            success, user_record, err = authenticate_user(login_user, login_pwd)
            if success:
                st.session_state.authenticated = True
                st.session_state.username = user_record["username"]
                st.session_state.role = user_record["role"]
                st.session_state.full_name = user_record["full_name"]
                st.rerun()
            else:
                st.error(err)

    else:
        st.subheader("New Account Registration")
        with st.form("register_form"):
            reg_name = st.text_input("Full Name")
            reg_user = st.text_input("Desired Username (alphanumeric)")
            reg_pwd = st.text_input(f"Password (min {MIN_PASSWORD_LENGTH} characters)", type="password")
            reg_role = st.selectbox("Role", ["borrower", "coordinator"])
            coord_key = st.text_input(
                "Coordinator Registration Secret Key (coordinators only)",
                type="password",
            )
            submit_reg = st.form_submit_button("Register Account")

        if submit_reg:
            success, msg = register_user(
                reg_user, reg_pwd, reg_name, reg_role,
                coord_key if reg_role == "coordinator" else "",
            )
            (st.success if success else st.error)(msg)

# ---------------------------------------------------------------------------
# VIEW: AUTHENTICATED PORTAL
# ---------------------------------------------------------------------------

else:
    actor_id = st.session_state.username
    current_role = st.session_state.role

    st.sidebar.markdown(f"### Logged in as **{st.session_state.full_name}**")
    st.sidebar.caption(f"Username: `{actor_id}` | Role: `{current_role.upper()}`")

    if st.sidebar.button("Log Out"):
        write_audit_log(actor_id, current_role, "LOGOUT", "User logged out")
        for key in ("username", "role", "full_name"):
            st.session_state[key] = None
        st.session_state.authenticated = False
        st.rerun()

    st.sidebar.markdown("---")

    nav_tabs = ["🔍 Search & Inventory", "📤 Checkout Asset", "📥 Return Asset", "⏰ Overdue Items"]
    if current_role == "coordinator":
        nav_tabs.append("📊 Analytics & Audit")
    selected_tab = st.sidebar.radio("Navigation", nav_tabs)

    # 1. Search & Inventory
    if selected_tab == "🔍 Search & Inventory":
        st.subheader("Asset Inventory & Search")
        col1, col2 = st.columns([3, 1])
        with col1:
            search_query = st.text_input(
                "Search by ID, Name, or Category", placeholder="e.g. Oscilloscope or Computing"
            )
        with col2:
            status_filter = st.selectbox(
                "Filter Status", ["ALL", "AVAILABLE", "CHECKED_OUT", "MAINTENANCE"]
            )

        sql = "SELECT asset_id, name, category, status FROM assets WHERE 1=1"
        params = []
        if search_query.strip():
            sql += " AND (asset_id LIKE %s OR name LIKE %s OR category LIKE %s)"
            pattern = f"%{search_query.strip()}%"
            params.extend([pattern, pattern, pattern])
        if status_filter != "ALL":
            sql += " AND status = %s"
            params.append(status_filter)

        st.dataframe(query_df(sql, tuple(params)), use_container_width=True)

    # 2. Checkout Asset
    elif selected_tab == "📤 Checkout Asset":
        st.subheader("Asset Checkout")
        avail = query_df("SELECT asset_id, name FROM assets WHERE status = 'AVAILABLE';")
        names = dict(zip(avail["asset_id"], avail["name"]))

        with st.form("checkout_form"):
            col1, col2 = st.columns(2)
            with col1:
                asset_to_borrow = st.selectbox(
                    "Select Available Asset",
                    options=list(names.keys()),
                    format_func=lambda x: f"{x} - {names.get(x, '')}",
                )
            with col2:
                duration = st.number_input("Loan Duration (Days)", min_value=1, max_value=30, value=7)
            submit_checkout = st.form_submit_button("Confirm Checkout")

        if submit_checkout:
            if not asset_to_borrow:
                st.warning("No asset selected.")
            else:
                ok, msg = perform_checkout(actor_id, current_role, asset_to_borrow, int(duration))
                (st.success if ok else st.error)(msg)

    # 3. Return Asset
    elif selected_tab == "📥 Return Asset":
        st.subheader("Return Checked-out Asset")
        base = (
            "SELECT c.asset_id, a.name, c.borrower_id, c.due_date "
            "FROM checkouts c JOIN assets a ON c.asset_id = a.asset_id "
            "WHERE c.returned_date IS NULL"
        )
        if current_role == "coordinator":
            active_loans = query_df(base + ";")
        else:
            active_loans = query_df(base + " AND c.borrower_id = %s;", (actor_id,))

        if active_loans.empty:
            st.info("No active checkouts found.")
        else:
            st.dataframe(active_loans, use_container_width=True)
            with st.form("return_form"):
                asset_to_return = st.selectbox(
                    "Select Asset to Return", active_loans["asset_id"].tolist()
                )
                submit_return = st.form_submit_button("Process Return")
            if submit_return:
                ok, msg = perform_return(actor_id, current_role, asset_to_return)
                (st.success if ok else st.error)(msg)

    # 4. Overdue Items
    elif selected_tab == "⏰ Overdue Items":
        st.subheader("Overdue Assets Report")
        df_overdue = query_df(
            """
            SELECT c.checkout_id, c.asset_id, a.name, c.borrower_id, c.checkout_date, c.due_date
            FROM checkouts c
            JOIN assets a ON c.asset_id = a.asset_id
            WHERE c.returned_date IS NULL AND c.due_date < %s
            ORDER BY c.due_date ASC;
            """,
            (fmt(utc_now()),),
        )
        if df_overdue.empty:
            st.success("No overdue items detected. All loans are compliant.")
        else:
            st.warning(f"Found {len(df_overdue)} overdue item(s).")
            st.dataframe(df_overdue, use_container_width=True)
            st.download_button(
                label="📥 Export Overdue Report (CSV)",
                data=df_overdue.to_csv(index=False).encode("utf-8"),
                file_name="overdue_report.csv",
                mime="text/csv",
            )

    # 5. Coordinator Analytics & Audit
    elif selected_tab == "📊 Analytics & Audit":
        if current_role != "coordinator":
            st.error("Access Denied: Coordinator credentials required.")
            write_audit_log(actor_id, current_role, "AUTH_FAILURE",
                            "Attempted unprivileged access to Analytics tab")
        else:
            st.subheader("Inventory Metrics & Category Distribution")
            df_counts = query_df("SELECT category, COUNT(*) AS count FROM assets GROUP BY category;")
            df_status = query_df("SELECT status, COUNT(*) AS count FROM assets GROUP BY status;")
            df_logs = query_df(
                """SELECT timestamp, actor_id, role, event_type, target_asset_id, details
                   FROM audit_logs ORDER BY log_id DESC LIMIT 50;"""
            )

            col1, col2 = st.columns(2)
            with col1:
                st.caption("Distribution by Category")
                if not df_counts.empty:
                    st.bar_chart(df_counts.set_index("category"))
            with col2:
                st.caption("Status Breakdown")
                if not df_status.empty:
                    st.bar_chart(df_status.set_index("status"))

            st.markdown("---")
            st.subheader("Security Audit Trail (Last 50 Events)")
            st.dataframe(df_logs, use_container_width=True)