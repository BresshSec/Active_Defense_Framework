#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ! -r /etc/os-release ]]; then
  echo 'Cannot identify this Linux distribution.' >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != kali ]]; then
  echo "This installer is for Kali Linux (detected: ${ID:-unknown})." >&2
  exit 1
fi

packages=(
  python3 python3-reportlab file poppler-utils qpdf pdfid pdf-parser
  clamav clamav-freshclam libimage-exiftool-perl
)

echo 'Installing Athena PDF Defense dependencies from Kali repositories...'
sudo apt-get update
sudo apt-get install -y "${packages[@]}"

echo
echo 'Checking commands:'
for command in python3 file pdfinfo pdfid qpdf clamscan pdftotext pdf-parser exiftool pdfimages; do
  if command -v "$command" >/dev/null 2>&1; then
    printf '  OK      %s\n' "$command"
  else
    printf '  MISSING %s\n' "$command"
  fi
done

echo
echo 'Installed. Run: python3 athena-pdf-defense.py'
echo 'ClamAV requires current signatures; check freshclam/service status before relying on its result.'

