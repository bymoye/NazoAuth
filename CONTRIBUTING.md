# Contributing to NazoAuth

## Licensing boundary

NazoAuth uses an open-source/commercial dual-licensing model:

- the public repository is licensed under `AGPL-3.0-or-later`;
- a copyright holder may separately offer commercial licenses for qualifying
  uses that cannot comply with the AGPL.

The commercial option is a separate written agreement. It is not an additional
license automatically granted by this repository.
The public license text is the unmodified AGPL in [LICENSE](LICENSE); the
commercial licensing notice is [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

## External code contributions

NazoAuth must retain enough copyright authority to offer the commercial
license without weakening the AGPL option. Therefore an external code
contribution must not be merged until the contributor has completed the
project's contributor license agreement (CLA). The CLA must, at minimum, grant
the project copyright holders a non-exclusive, perpetual, worldwide,
irrevocable right to use, modify, distribute, sublicense, and relicense the
contribution, including under both the public AGPL license and separate
commercial licenses.

Merely opening a pull request, signing off a commit, or accepting the Developer
Certificate of Origin does not by itself grant commercial relicensing rights.
Until a CLA workflow is published, external contributors should open an issue
to discuss a proposed change; maintainers must not merge the contributed code.

Dependency-only automation updates remain governed by the licenses of the
updated dependencies and the repository's supply-chain policy. Maintainers must
not represent third-party code as covered by a NazoAuth commercial license.

Code contributions must follow the workspace boundaries in
[docs/project/architecture.md](docs/project/architecture.md) and the mandatory
test layout in [docs/project/testing.md](docs/project/testing.md). The latter is
enforced by `python scripts/verify_static_contracts.py --check`.

Documentation, issue reports, and suggestions that contain no contributed code
do not require a CLA, but their authors must avoid including third-party
confidential information or material they are not authorized to submit.
