#!/usr/bin/env bash
set -e

echo "=== Instalacia GitHub CLI ==="
sudo apt-get install -y gh

echo ""
echo "=== Prihlasenie (otvori sa prehliadac / da ti kod na zadanie) ==="
echo "Vyber: GitHub.com -> HTTPS -> Login with a web browser"
gh auth login

echo ""
echo "=== Nastavenie git, aby pouzival gh prihlasenie pre push/pull ==="
gh auth setup-git

echo ""
echo "=== Nastavenie git user.name / user.email (chyba .gitconfig) ==="
GH_NAME=$(gh api user --jq .name 2>/dev/null)
GH_LOGIN=$(gh api user --jq .login 2>/dev/null)
git config --global user.name "${GH_NAME:-$GH_LOGIN}"
git config --global user.email "krempasky.lukas.it@gmail.com"

echo ""
echo "=== Over ==="
gh auth status
git config --global user.name
git config --global user.email
