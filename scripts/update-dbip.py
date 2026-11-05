#!/usr/bin/env python3
"""Install monthly DB-IP Lite City/ASN MMDBs, validate, then restart the app.

Run on the Docker host. The existing app container supplies geoip2, so no
Python packages or root cron are needed on the host. Compatibility filenames
are retained for the upstream GeoIP reader. Requires DB-IP attribution in UI.
"""
import argparse
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timezone


def update(directory, container):
    directory.mkdir(parents=True, exist_ok=True)
    month = datetime.now(timezone.utc).strftime('%Y-%m')
    manifest = directory / 'dbip-source.json'
    old = json.loads(manifest.read_text()) if manifest.exists() else {}
    names = {'city': 'GeoLite2-City.mmdb', 'asn': 'GeoLite2-ASN.mmdb'}
    if old.get('release') == month and all((directory / n).is_file() for n in names.values()):
        print('DB-IP Lite already current: ' + month)
        return
    files = {}
    with tempfile.TemporaryDirectory(prefix='.dbip-', dir=directory) as temporary:
        for kind, name in names.items():
            url = f'https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz'
            compressed = Path(temporary) / (name + '.gz')
            request = urllib.request.Request(url, headers={'User-Agent': 'MikroTik-Insights-DBIP-Updater/1'})
            with urllib.request.urlopen(request, timeout=120) as response, compressed.open('wb') as target:
                shutil.copyfileobj(response, target)
            unpacked = Path(temporary) / name
            with gzip.open(compressed, 'rb') as source, unpacked.open('wb') as target:
                shutil.copyfileobj(source, target)
            if not 100_000 < unpacked.stat().st_size < 1_000_000_000:
                raise ValueError('Unexpected MMDB size: ' + kind)
            files[kind] = {'url': url, 'sha256': hashlib.file_digest(unpacked.open('rb'), 'sha256').hexdigest()}

        relative = Path(temporary).name
        validation = f'''import geoip2.database
from pathlib import Path
root = Path('/app/maxmind') / {relative!r}
with geoip2.database.Reader(str(root / 'GeoLite2-City.mmdb')) as reader:
    assert reader.city('8.8.8.8').country.iso_code
    assert reader.city('2606:4700:4700::1111').country.iso_code
with geoip2.database.Reader(str(root / 'GeoLite2-ASN.mmdb')) as reader:
    assert reader.asn('8.8.8.8').autonomous_system_number
    assert reader.asn('2606:4700:4700::1111').autonomous_system_number
print('City/ASN IPv4 and IPv6 lookups validated')
'''
        subprocess.run(['docker', 'exec', '-i', container, 'python3', '-'], input=validation, text=True, check=True)
        for name in names.values():
            os.replace(Path(temporary) / name, directory / name)
        record = {'provider': 'DB-IP Lite', 'release': month, 'license': 'CC BY 4.0',
                  'attribution_url': 'https://db-ip.com', 'updated_at': datetime.now(timezone.utc).isoformat(),
                  'files': files}
        temporary_manifest = directory / '.dbip-source.json.tmp'
        temporary_manifest.write_text(json.dumps(record, indent=2) + '\n')
        os.replace(temporary_manifest, manifest)

    # Reload the receiver and API processes, whose GeoIP readers are separate.
    subprocess.run(['docker', 'restart', container], check=True, stdout=subprocess.DEVNULL)
    print('Installed DB-IP Lite ' + month + '; app restarted with persistent data retained')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--container', default='mikrotik-insights-staging')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    with (args.directory / '.update.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        update(args.directory.resolve(), args.container)
