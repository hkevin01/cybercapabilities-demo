#!/bin/bash

echo "Testing cybersecurity demo components..."

# Test 1: Check if vulnerable app can start
echo "1. Testing vulnerable app startup..."
cd apps/vulnerable-webapp
timeout 5s npm start &
VULN_PID=$!
sleep 3
if kill -0 $VULN_PID 2>/dev/null; then
    echo "✅ Vulnerable app started successfully"
    kill $VULN_PID
else
    echo "❌ Vulnerable app failed to start"
fi
cd ../..

# Test 2: Check if secure app can start 
echo "2. Testing secure app startup..."
cd apps/secure-webapp
timeout 5s node src/app-final.js &
SECURE_PID=$!
sleep 3
if kill -0 $SECURE_PID 2>/dev/null; then
    echo "✅ Secure app started successfully"
    kill $SECURE_PID
else
    echo "❌ Secure app failed to start"
fi
cd ../..

# Test 3: Check if reverse engineering challenge builds
echo "3. Testing reverse engineering challenge build..."
cd apps/reverse-engineering/challenge-src
if make > /dev/null 2>&1; then
    echo "✅ Reverse engineering challenge built successfully"
else
    echo "❌ Reverse engineering challenge failed to build"
fi
cd ../../..

# Test 4: Check if Python keygen works
echo "4. Testing Python keygen..."
cd apps/reverse-engineering/analysis
if python3 keygen.py testuser > /dev/null 2>&1; then
    echo "✅ Python keygen works"
else
    echo "❌ Python keygen failed"
fi
cd ../../..

echo "Component testing complete!"
