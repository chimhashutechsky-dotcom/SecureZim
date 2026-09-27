#!/bin/bash
set -e

echo "=== SecureZim Authentication Setup & Verification ==="
echo ""

# Step 1: Check Python version
echo "✓ Checking Python version..."
python --version

# Step 2: Install dependencies
echo "✓ Installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

# Step 3: Setup environment
echo "✓ Setting up environment variables..."
if [ ! -f .env ]; then
    cp .env.example .env
    # Generate a strong secret key
    SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
    # Update .env with the generated secret
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/your-super-secret-key-change-this-in-production/$SECRET_KEY/" .env
    else
        sed -i "s/your-super-secret-key-change-this-in-production/$SECRET_KEY/" .env
    fi
    echo "  Generated SECRET_KEY and saved to .env"
else
    echo "  .env already exists"
fi

# Step 4: Setup database
echo "✓ Initializing database..."
python << 'EOF'
from app.db import engine, Base
Base.metadata.create_all(bind=engine)
print("  Database tables created successfully")
EOF

# Step 5: Run tests
echo "✓ Running authentication tests..."
python -m pytest tests/test_auth.py -v --tb=short

# Step 6: Create sample companies and users
echo "✓ Creating sample data for testing..."
python << 'EOF'
from app.db import SessionLocal
from app.models import Company, User
from app.auth import hash_password

db = SessionLocal()

# Check if sample data already exists
existing = db.query(Company).filter(Company.name == "Demo Corp").first()
if existing:
    print("  Sample data already exists")
else:
    # Create Demo Corp
    demo_corp = Company(name="Demo Corp")
    db.add(demo_corp)
    db.flush()
    
    # Create admin user for Demo Corp
    demo_admin = User(
        company_id=demo_corp.id,
        email="admin@democorp.com",
        hashed_password=hash_password("DemoPass123"),
        full_name="Demo Administrator",
        is_active=True
    )
    db.add(demo_admin)
    
    # Create Test Security
    test_sec = Company(name="Test Security")
    db.add(test_sec)
    db.flush()
    
    # Create admin user for Test Security
    test_admin = User(
        company_id=test_sec.id,
        email="admin@testsecurity.com",
        hashed_password=hash_password("TestPass123"),
        full_name="Test Administrator",
        is_active=True
    )
    db.add(test_admin)
    
    db.commit()
    
    print("  Created Demo Corp (admin@democorp.com / DemoPass123)")
    print("  Created Test Security (admin@testsecurity.com / TestPass123)")

db.close()
EOF

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "To start the app, run:"
echo "  uvicorn app.main:app --reload"
echo ""
echo "Then visit http://localhost:8000/docs for API documentation"
echo ""
echo "Test Credentials:"
echo "  Company 1: Demo Corp"
echo "    Email: admin@democorp.com"
echo "    Password: DemoPass123"
echo ""
echo "  Company 2: Test Security"
echo "    Email: admin@testsecurity.com"
echo "    Password: TestPass123"
echo ""
echo "Next steps:"
echo "  1. Start the app with: uvicorn app.main:app --reload"
echo "  2. Log in at /docs and try the endpoints"
echo "  3. Create assets and run scans"
echo "  4. Verify data isolation between companies"
echo ""
echo "Production deployment:"
echo "  - Review .env and use strong SECRET_KEY"
echo "  - Use PostgreSQL instead of SQLite"
echo "  - Enable HTTPS"
echo "  - See AUTHENTICATION.md for more details"
echo ""
