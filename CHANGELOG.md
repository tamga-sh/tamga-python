# Changelog

All notable changes to this project will be documented in this file. This file is maintained by
[release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org/) history — do not hand-edit entries
below the `[Unreleased]` header.

## [0.2.0](https://github.com/tamga-sh/tamga-python/compare/v0.1.2...v0.2.0) (2026-08-13)


### ⚠ BREAKING CHANGES

* offline license files must be format v2 (`alg` ending in `+v2`). v1 files are rejected outright with no compatibility path. The `crypto.naive_key` module is removed, not deprecated.

### Features

* SDK v2 security contract — license-file HKDF, offline format v2, HTTP 429 handling ([9f3ac63](https://github.com/tamga-sh/tamga-python/commit/9f3ac63f6f36cc113eea4e85a03996f6f015b59c))

## [0.1.2](https://github.com/tamga-sh/tamga-python/compare/v0.1.1...v0.1.2) (2026-08-12)


### Bug Fixes

* enforce curve/key-size validation in ECDSA and RSA verifiers ([856c4ca](https://github.com/tamga-sh/tamga-python/commit/856c4caeed4ebf8ba2ef5ae280327914403e4820))
* enforce P-256 curve in verify_p256 (curve-confusion vulnerability) ([56feacf](https://github.com/tamga-sh/tamga-python/commit/56feacf19665ac4384cdb6ff04b168177c68d730))
* enforce RSA key-size range in verify_pkcs1v15/verify_pss ([60eff42](https://github.com/tamga-sh/tamga-python/commit/60eff425ca0c05dc32d3a96a2d13b1ccab248c88))
* harden checkout parsing against malformed-but-not-forged input ([624ac6f](https://github.com/tamga-sh/tamga-python/commit/624ac6fe56b27f6f70bac4fa8127e1b2af2c251f))
* harden checkout parsing against malformed-but-not-forged input ([d45c35a](https://github.com/tamga-sh/tamga-python/commit/d45c35af0b68c1938306b67c0d6a0543edd1538c))


### Documentation

* fix stale scaffold-only status and back-fill security-reviewer history in CLAUDE.md ([356f8cd](https://github.com/tamga-sh/tamga-python/commit/356f8cd022ccef5632128471ba907fde13b3d125))
* fix stale scaffold-only status and back-fill security-reviewer history in CLAUDE.md ([ebf799c](https://github.com/tamga-sh/tamga-python/commit/ebf799c8d857a99ac812fd07b810a3ae163f4bb0))

## [0.1.1](https://github.com/tamga-sh/tamga-python/compare/v0.1.0...v0.1.1) (2026-08-11)


### Documentation

* add CODE_OF_CONDUCT.md and .editorconfig ([9ec6bc4](https://github.com/tamga-sh/tamga-python/commit/9ec6bc43729282decccf84018d557ce53931f8cb))

## 0.1.0 (2026-08-11)


### Features

* implement license/machine validation, checkout crypto, and error model (Sections B-K) ([d0524d8](https://github.com/tamga-sh/tamga-python/commit/d0524d822e4b323b071906e2b19a71fe1a90d069))


### Bug Fixes

* **ci:** gate PyPI publish on release-please's own job output ([b352422](https://github.com/tamga-sh/tamga-python/commit/b35242271ffb6dfb845cadd07dda9aacfc6791ae))


### Documentation

* add README, examples, CHANGELOG, CONTRIBUTING, SECURITY, GitHub templates (Sections L-M) ([6307ceb](https://github.com/tamga-sh/tamga-python/commit/6307cebc047d7ab3d90fa41b2185baac0632b6ff))
* remove dead docs/plans references, add status badges where CI is live ([7971490](https://github.com/tamga-sh/tamga-python/commit/79714904468fc6abcf5893c53a4b491e32eca768))

## [Unreleased]
