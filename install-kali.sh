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

echo 'Installing Athena Defense dependencies from Kali repositories...'
sudo apt-get update
sudo apt-get install -y "${packages[@]}"

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$project_dir/Athenadef.py" ]]; then
  echo 'Athenadef.py is missing from this repository.' >&2
  exit 1
fi
printf '#!/usr/bin/env bash\nexec python3 %q "$@"\n' "$project_dir/Athenadef.py" |
  sudo tee /usr/local/bin/Athenadef >/dev/null
sudo chmod 755 /usr/local/bin/Athenadef

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
echo 'Installed. Run: Athenadef'
echo 'ClamAV requires current signatures; check freshclam/service status before relying on its result.'

