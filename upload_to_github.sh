#!/bin/bash
#
# Script to upload to GitHub
# Run this after creating a new repository on GitHub
#

REPO_NAME="iot-ids-testbed"
GITHUB_USER="AMALKRISHNAUR"

echo "========================================"
echo "GitHub Upload Script"
echo "========================================"
echo ""

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "Initializing git repository..."
    git init
    git add -A
    git commit -m "Initial commit: IoT IDS Testbed with TinyML"
fi

echo ""
echo "Instructions:"
echo "============="
echo ""
echo "1. Go to: https://github.com/new"
echo ""
echo "2. Create a new repository with these settings:"
echo "   - Repository name: $REPO_NAME"
echo "   - Description: IoT Intrusion Detection System Testbed using Contiki-NG, Cooja, and TinyML"
echo "   - Visibility: Public"
echo "   - Do NOT initialize with README (we already have one)"
echo ""
echo "3. After creating the repo, run these commands:"
echo ""
echo "   git remote add origin https://github.com/$GITHUB_USER/$REPO_NAME.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "========================================"
echo ""

# Ask if user wants to proceed
read -p "Have you created the repository on GitHub? (y/n): " answer

if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    # Check if remote already exists
    if git remote | grep -q "origin"; then
        echo "Remote 'origin' already exists. Updating URL..."
        git remote set-url origin "https://github.com/$GITHUB_USER/$REPO_NAME.git"
    else
        echo "Adding remote origin..."
        git remote add origin "https://github.com/$GITHUB_USER/$REPO_NAME.git"
    fi
    
    echo "Pushing to GitHub..."
    git branch -M main
    git push -u origin main
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Successfully pushed to GitHub!"
        echo "  URL: https://github.com/$GITHUB_USER/$REPO_NAME"
    else
        echo ""
        echo "✗ Push failed. Please check your credentials and try again."
    fi
else
    echo ""
    echo "Please create the repository first, then run this script again."
fi
