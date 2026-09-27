# Database Migration Guide

If you have an existing SecureZim database with companies, assets, scans, and findings, follow this guide to add authentication.

## For SQLite

### Step 1: Backup Your Database
```bash
cp securezim.db securezim.db.backup
```

### Step 2: Create the Users Table Manually

Start a Python shell in your project:
```bash
python
```

Then run:
```python
from app.db import engine
from app.models import User, Base

# Create only the users table (other tables already exist)
Base.metadata.tables['users'].create(engine, checkfirst=True)
print("Users table created successfully")
```

### Step 3: Assign Existing Companies to Users

```python
from app.db import SessionLocal
from app.models import Company, User
from app.auth import hash_password

db = SessionLocal()

# For each existing company, create an admin user
companies = db.query(Company).all()

for company in companies:
    # Check if company already has a user
    existing_user = db.query(User).filter(User.company_id == company.id).first()
    
    if not existing_user:
        # Create an admin user for this company
        admin_user = User(
            company_id=company.id,
            email=f"admin@{company.name.lower().replace(' ', '')}.com",
            hashed_password=hash_password("temporary-password-change-me"),
            full_name=f"{company.name} Administrator",
            is_active=True
        )
        db.add(admin_user)
        print(f"Created user for {company.name}: {admin_user.email}")

db.commit()
db.close()
print("Migration complete!")
```

### Step 4: Update Admin Passwords

Each admin should log in and change their temporary password via the login endpoint. Or manually update in the database:

```python
from app.db import SessionLocal
from app.models import User
from app.auth import hash_password

db = SessionLocal()
user = db.query(User).filter(User.email == "admin@company.com").first()
user.hashed_password = hash_password("new-secure-password")
db.commit()
db.close()
```

## For PostgreSQL/MySQL

### Step 1: Backup Your Database

```bash
# PostgreSQL
pg_dump -U user -h localhost securezim > securezim.sql

# MySQL
mysqldump -u user -p securezim > securezim.sql
```

### Step 2: Create the Users Table

Update your database connection and run:

```python
from app.db import engine
from app.models import User, Base

# Create the users table
Base.metadata.tables['users'].create(engine, checkfirst=True)
print("Users table created successfully")
```

### Step 3: Populate Users (Same as SQLite)

Use the Python script above to assign users to existing companies.

## Verification

After migration, verify the users table was created:

```bash
# SQLite
sqlite3 securezim.db ".schema users"

# PostgreSQL
psql -U user -h localhost -d securezim -c "\d users"

# MySQL
mysql -u user -p securezim -e "DESCRIBE users;"
```

You should see columns: `id`, `company_id`, `email`, `hashed_password`, `full_name`, `is_active`, `created_at`, `updated_at`.

## Testing the Migration

1. Start the application
2. Log in with one of the created admin users
3. Verify you can access only assets/scans for that company
4. Create a new user via the register endpoint
5. Verify data isolation between companies

## Rollback

If something goes wrong, restore from backup:

```bash
# SQLite
rm securezim.db
cp securezim.db.backup securezim.db

# PostgreSQL
psql -U user -h localhost < securezim.sql

# MySQL
mysql -u user -p securezim < securezim.sql
```
