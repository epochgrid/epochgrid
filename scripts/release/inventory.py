#!/usr/bin/env python3
"""Capture the compiled dependency graph and emit subject-bound SPDX 2.3 inventories."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import urllib.parse


def tree_digest(directory):
    value = hashlib.sha256()
    for path in sorted(directory.rglob('*')):
        if path.is_file():
            value.update(path.relative_to(directory).as_posix().encode() + b'\0')
            value.update(hashlib.sha256(path.read_bytes()).digest())
    return value.hexdigest()


def compiled_inventory(metadata, compiled):
    packages = {p['id']: p for p in metadata['packages']}
    nodes = {p['id']: p for p in metadata['resolve']['nodes']}
    runtime, pending = set(), list(metadata['workspace_members'])
    while pending:
        identifier = pending.pop()
        if identifier in runtime:
            continue
        package = packages[identifier]
        if any('proc-macro' in target['kind'] for target in package['targets']):
            continue
        runtime.add(identifier)
        for dep in nodes[identifier]['deps']:
            if any(kind['kind'] is None for kind in dep['dep_kinds']):
                pending.append(dep['pkg'])
    result = []
    for identifier in sorted(compiled):
        package = packages[identifier]
        if identifier in metadata['workspace_members']:
            continue
        name, version = package['name'], package['version']
        # rayon-core uses Cargo's links field solely to enforce a single Rust
        # threadpool implementation; its reviewed build.rs links no native code.
        singleton_rust = name == 'rayon-core' and version == '1.13.0'
        if package.get('links') and name not in {'libsqlite3-sys', 'openssl-sys', 'ring'} and not singleton_rust:
            raise ValueError('Unreviewed compiled native link provider: ' + name)
        result.append(dict(name=name, version=version, kind='rust',
                           usage='runtime' if identifier in runtime else 'build',
                           license=package['license'] or 'NOASSERTION',
                           source=package['source'], features=sorted(nodes[identifier]['features'])))
        directory = Path(package['manifest_path']).parent
        if name == 'libsqlite3-sys':
            sql = (directory / 'sqlcipher/sqlite3.c').read_text()
            for component, pattern in [('SQLCipher', r'#define CIPHER_VERSION_NUMBER ([0-9.]+)'),
                                       ('SQLite', r'#define SQLITE_VERSION\s+"([0-9.]+)"')]:
                match = re.search(pattern, sql)
                if not match:
                    raise ValueError('Native dependency version missing: ' + component)
                result.append(dict(name=component, version=match[1], kind='native', usage='runtime',
                                   license='NOASSERTION', source='libsqlite3-sys@' + version,
                                   source_sha256=tree_digest(directory / 'sqlcipher')))
        if name == 'openssl-src':
            result.append(dict(name='OpenSSL', version=version.split('+', 1)[1], kind='native',
                               usage='runtime', license='Apache-2.0', source='openssl-src@' + version,
                               source_sha256=tree_digest(directory / 'openssl')))
        if name == 'ring':
            result.append(dict(name='ring-vendored-crypto', version=version, kind='native', usage='runtime',
                               license='NOASSERTION', source='ring@' + version,
                               includes=['BoringSSL-derived code', 'fiat-crypto-derived code'],
                               source_sha256=tree_digest(directory)))
    if {x['name'] for x in result if x['kind'] == 'native'} != {
            'SQLCipher', 'SQLite', 'OpenSSL', 'ring-vendored-crypto'}:
        raise ValueError('Reviewed native component coverage changed')
    return result


def spdx(components, subject, subject_digest, epoch):
    packages = [dict(SPDXID='SPDXRef-Subject', name=subject, downloadLocation='NOASSERTION',
                     filesAnalyzed=False, checksums=[dict(algorithm='SHA256', checksumValue=subject_digest)],
                     licenseConcluded='NOASSERTION', licenseDeclared='NOASSERTION', copyrightText='NOASSERTION')]
    relationships = [dict(spdxElementId='SPDXRef-DOCUMENT', relationshipType='DESCRIBES',
                          relatedSpdxElement='SPDXRef-Subject')]
    for index, item in enumerate(components):
        identifier = f'SPDXRef-Component-{index}'
        package = dict(SPDXID=identifier, name=item['name'], versionInfo=item['version'],
                       downloadLocation='NOASSERTION', filesAnalyzed=False,
                       licenseConcluded='NOASSERTION', licenseDeclared=item['license'],
                       copyrightText='NOASSERTION', comment=json.dumps(item, sort_keys=True))
        if 'source_sha256' in item:
            package['sourceInfo'] = 'Vendored source tree SHA256: ' + item['source_sha256']
        if item['kind'] in {'rust', 'deb'}:
            ecosystem = 'cargo/' if item['kind'] == 'rust' else 'deb/ubuntu/'
            purl = 'pkg:' + ecosystem + urllib.parse.quote(item['name'], safe='') + '@' + urllib.parse.quote(item['version'], safe='')
            if item['kind'] == 'deb':
                purl += '?arch=amd64&distro=ubuntu-24.04'
            package['externalRefs'] = [dict(referenceCategory='PACKAGE-MANAGER', referenceType='purl',
                                            referenceLocator=purl)]
        packages.append(package)
        relationships.append(dict(spdxElementId='SPDXRef-Subject',
                                  relationshipType='BUILD_DEPENDENCY_OF' if item['usage'] == 'build' else 'DEPENDS_ON',
                                  relatedSpdxElement=identifier))
        if item['usage'] == 'build':
            relationships[-1].update(spdxElementId=identifier, relatedSpdxElement='SPDXRef-Subject')
    return dict(spdxVersion='SPDX-2.3', dataLicense='CC0-1.0', SPDXID='SPDXRef-DOCUMENT',
                name=subject, documentNamespace='https://epochgrid.org/spdx/' + subject_digest + '/' + subject,
                creationInfo=dict(creators=['Tool: epochgrid-inventory-1'],
                                  created=datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')),
                packages=packages, relationships=relationships)


def validate_spdx(data, digest):
    # This producer accepts a deliberately small SPDX subset. Full SPDX schema
    # validation is also performed by the release workflow before signing.
    if data['spdxVersion'] != 'SPDX-2.3' or data['dataLicense'] != 'CC0-1.0':
        raise ValueError('Unsupported SPDX version/license')
    ids = [p['SPDXID'] for p in data['packages']]
    if len(ids) != len(set(ids)) or len(ids) < 2:
        raise ValueError('Missing/duplicate SPDX packages')
    subject = [p for p in data['packages'] if p['SPDXID'] == 'SPDXRef-Subject']
    if len(subject) != 1 or subject[0]['checksums'] != [dict(algorithm='SHA256', checksumValue=digest)]:
        raise ValueError('SBOM subject mismatch')
    for relation in data['relationships']:
        if any(relation[key] not in ids + ['SPDXRef-DOCUMENT'] for key in ('spdxElementId', 'relatedSpdxElement')):
            raise ValueError('Dangling SPDX relationship')
    import jsonschema
    schema = json.loads(Path(__file__).with_name('spdx-schema.json').read_text())
    jsonschema.Draft7Validator(schema).validate(data)
