#!/bin/bash
# setup_repo.sh
# Run this ONCE after creating the empty GitHub repo.
# It initialises git, creates branches, and pushes everything.
#
# Usage:
#   1. Create an empty repo on GitHub named: cosmic-siem
#   2. Copy this script into the cosmic-siem folder you downloaded from Claude
#   3. Run: bash setup_repo.sh https://github.com/YOUR_ORG/cosmic-siem.git

set -e

REMOTE_URL=$1

if [ -z "$REMOTE_URL" ]; then
  echo "Usage: bash setup_repo.sh https://github.com/YOUR_ORG/cosmic-siem.git"
  exit 1
fi

echo "==> Initialising git..."
git init
git add .
git commit -m "docs(arch): initial architecture document and repo structure"

echo "==> Creating branches..."
git branch -M main
git checkout -b dev
git checkout main

echo "==> Adding remote..."
git remote add origin "$REMOTE_URL"

echo "==> Pushing main branch..."
git push -u origin main

echo "==> Pushing dev branch..."
git push -u origin dev

echo ""
echo "✅ Done! Your repo is live."
echo ""
echo "Next steps:"
echo "  1. Go to your GitHub repo → Projects → Create a project board"
echo "  2. Add columns: Backlog / In Progress / Done / Blocked"
echo "  3. Add Day 3 task as a card in Backlog: 'Install Wazuh on test server'"
echo "  4. Share the repo link with Siddharth"
