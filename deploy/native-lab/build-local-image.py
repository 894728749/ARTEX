#!/usr/bin/env python3
"""Build the native lab image offline from an explicitly selected Linux toolchain.

Only system binaries/libraries and the repository ptrace probe enter the image.
No home directory, daemon socket, application config or credentials are copied.
The generated manifest records every payload hash and tool version for review.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--tag', default='artex-native-lab:verified-local')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('run inside the configured Linux lab')
    args.output.mkdir(parents=True, exist_ok=False)
    root = args.output / 'rootfs'
    root.mkdir()
    copied = {}

    def add(path):
        path = Path(path)
        if not path.is_absolute() or not str(path).startswith(('/usr/', '/lib/', '/lib64/', '/bin/', '/sbin/')):
            raise ValueError('unexpected system payload path: ' + str(path))
        if not path.is_file() or str(path) in copied:
            return
        data = path.read_bytes()
        dest = root / str(path).lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        copied[str(path)] = hashlib.sha256(data).hexdigest()

    def binary(path):
        add(path)
        # ldd is used only on the explicit, installed system toolchain list.
        proc = subprocess.run(['ldd', str(path)], capture_output=True, text=True)
        for item in re.findall(r'(/[^\s()]+)', proc.stdout):
            if Path(item).is_file():
                add(item)

    commands = ['/usr/bin/gdb', '/usr/bin/python3', '/bin/sh', '/usr/bin/test',
                '/sbin/ldconfig', '/usr/bin/true', '/usr/bin/false', '/usr/bin/cat']
    for path in commands:
        binary(path)
    stdlib = Path(subprocess.check_output(['/usr/bin/python3', '-c',
        'import sysconfig; print(sysconfig.get_path("stdlib"))'], text=True).strip())
    for directory in [stdlib, Path('/usr/share/gdb')]:
        for path in directory.rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and 'site-packages' not in path.parts:
                add(path)
                if path.suffix == '.so':
                    binary(path)
    for name in ['libasan.so', 'libubsan.so', 'libstdc++.so.6', 'libgcc_s.so.1']:
        path = subprocess.check_output(['gcc', '-print-file-name=' + name], text=True).strip()
        if not Path(path).is_absolute():
            raise RuntimeError('missing installed runtime: ' + name)
        binary(path)
        # DT_NEEDED resolves by SONAME in the standard library directory.
        real = Path(path).resolve()
        add(real)
        for candidate in real.parent.glob(name.split('.so')[0] + '.so*'):
            if candidate.is_file():
                binary(candidate)
    for path in [Path('/lib/x86_64-linux-gnu/libthread_db.so.1'), Path('/lib64/ld-linux-x86-64.so.2')]:
        binary(path)
    for directory in ['etc', 'tmp', 'work/deps', 'work/loader', 'usr/local/bin']:
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / 'tmp').chmod(0o1777)
    (root / 'etc/ld.so.conf').write_text('/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu\n/lib64\n')
    source = Path(__file__).with_name('ptrace_probe.c')
    subprocess.run(['gcc', '-O0', '-g', '-fno-pie', '-no-pie', str(source),
                    '-o', str(root / 'usr/local/bin/artex-ptrace-probe')], check=True)
    versions = {}
    for tool in ['gdb', 'gcc', 'python3', 'ldd']:
        result = subprocess.run([tool, '--version'], capture_output=True, text=True, check=True)
        versions[tool] = result.stdout.splitlines()[0]
    payload = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(root.rglob('*')) if p.is_file()}
    manifest = {'source': 'explicit installed Linux system toolchain', 'versions': versions,
                'architecture': os.uname().machine, 'kernel_at_build': os.uname().release,
                'payload_sha256': payload}
    (root / 'usr/local/share').mkdir(parents=True, exist_ok=True)
    (root / 'usr/local/share/artex-toolchain.json').write_text(json.dumps(manifest, indent=2))
    (args.output / 'Dockerfile').write_text('FROM scratch\nCOPY rootfs /\nRUN ["/sbin/ldconfig"]\nWORKDIR /work\nUSER 65534:65534\nENTRYPOINT ["/usr/bin/false"]\n')
    subprocess.run(['docker', 'build', '--network=none', '--tag', args.tag, str(args.output)], check=True)
    image = subprocess.check_output(['docker', 'image', 'inspect', args.tag, '--format', '{{.Id}}'], text=True).strip()
    manifest['image'] = image
    (args.output / 'image-manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({'image': image, 'manifest': str(args.output / 'image-manifest.json'), 'files': len(payload)}))


if __name__ == '__main__':
    main()
