#!/bin/bash

echo "🛡️ SIEM System - Quick Start"
echo "============================"
echo ""

echo "Step 1: Installing dependencies..."
pip3 install -r requirements.txt

echo ""
echo "Step 2: Initializing database..."
python3 -c "from database import Database; db = Database(); db.initialize()"

echo ""
echo "✅ Setup complete!"
echo ""
echo "To start the system:"
echo "1. Run: python3 main_clean.py"
echo "2. In new terminal: python3 -m http.server 8000"
echo "3. Open: http://localhost:8000/login.html"
echo "4. Login: admin / arsath"
echo ""
