# Changelog

All notable changes to this project will be documented in this file. This file is maintained by
[release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org/) history — do not hand-edit entries
below the `[Unreleased]` header.

## [1.1.3](https://github.com/tamga-sh/tamga-python/compare/v1.1.2...v1.1.3) (2026-09-05)


### Bug Fixes

* carry the error meta, type the two key-material 422s, and adopt the machine a 409 names ([3c1a623](https://github.com/tamga-sh/tamga-python/commit/3c1a6234a900e910dbdfbc319d4332d19a19af46))
* **checkout:** reject a fast-path machine whose fingerprint doesn't match ([8e33802](https://github.com/tamga-sh/tamga-python/commit/8e33802f6c3bbab766da0a584fe985fed3e3538b))
* error meta, key-material 422s, meta.machineId fast path (1.1.3) ([a7f9c54](https://github.com/tamga-sh/tamga-python/commit/a7f9c5406e2db0a78586ace927b7525f4ef5db72))


### Documentation

* fix three remaining doc contradictions with the pre-patch/API-patch reframing ([05498a9](https://github.com/tamga-sh/tamga-python/commit/05498a990d4710d24a46e91a65066b8f2e337cf5))
* reword the two remaining stale empty-key-set claims to the pre-patch framing ([9b46745](https://github.com/tamga-sh/tamga-python/commit/9b46745c3cec33beaf4355c35a062439fb42eabf))

## [1.1.2](https://github.com/tamga-sh/tamga-python/compare/v1.1.1...v1.1.2) (2026-09-04)


### Bug Fixes

* **deps:** require Python 3.9.2 so the lockfile can drop cryptography 47 ([#35](https://github.com/tamga-sh/tamga-python/issues/35)) ([77da7bb](https://github.com/tamga-sh/tamga-python/commit/77da7bb2ec1ff0e2a5af7c7abe31ac955e1dcabe))

## [1.1.1](https://github.com/tamga-sh/tamga-python/compare/v1.1.0...v1.1.1) (2026-08-21)


### Bug Fixes

* canonicalise fingerprint components so one machine cannot hold three seats ([d323cb2](https://github.com/tamga-sh/tamga-python/commit/d323cb25eaa951f2bbeb2213636d6ddc789bcc5c))
* keep a licence's identity intact across rotation, download and activation ([fd8e199](https://github.com/tamga-sh/tamga-python/commit/fd8e19960eace9801e4dc43a93f1794187142f69))
* read and download artifacts without handing the licence key to storage ([134fa2c](https://github.com/tamga-sh/tamga-python/commit/134fa2c44b9d19ca90f75e221a5891dfbd73f914))
* verify offline files against the key set their kid names ([4a63ab3](https://github.com/tamga-sh/tamga-python/commit/4a63ab36871bd8efcf6c4fa47d1e592f1b77f445))


### Documentation

* record the kid rule, the 403, and the ordering that must not be inverted ([058ade7](https://github.com/tamga-sh/tamga-python/commit/058ade709d92ec1c28cdbc6693585fbffe141792))

## [1.1.0](https://github.com/tamga-sh/tamga-python/compare/v1.0.4...v1.1.0) (2026-08-21)


### Features

* correct two Policy typed-surface defects (M38, M9) ([d2ecc1c](https://github.com/tamga-sh/tamga-python/commit/d2ecc1c6bbfc123fbe5d2c2e35ab08da0272c1d3))
* drop the two policy limits no serializer emits ([fefbac0](https://github.com/tamga-sh/tamga-python/commit/fefbac07e54587bc151961e91629931f16857c19))
* read the check-in cadences the server can actually store ([eb11d3e](https://github.com/tamga-sh/tamga-python/commit/eb11d3ea0dac13016bc1599f068f5fbfefab6506))


### Bug Fixes

* keep release-please looking for the tags this repo actually has ([#32](https://github.com/tamga-sh/tamga-python/issues/32)) ([8481316](https://github.com/tamga-sh/tamga-python/commit/8481316ef63f8d4e1f74cf44787bd4c354fbe2e0))
* let release-please see its own config, so __version__ tracks releases ([#30](https://github.com/tamga-sh/tamga-python/issues/30)) ([5b32697](https://github.com/tamga-sh/tamga-python/commit/5b326971f76b7736b1b684ee63f38ab4055061a4))


### Documentation

* stop implying the cadence enum is the whole check-in schedule ([310a263](https://github.com/tamga-sh/tamga-python/commit/310a263e8f8a96de5fb7a3c9abc17491c01aa07a))

## [1.0.4](https://github.com/tamga-sh/tamga-python/compare/v1.0.3...v1.0.4) (2026-08-21)


### Bug Fixes

* align SDK with the current tamga-api server contract ([24c1556](https://github.com/tamga-sh/tamga-python/commit/24c15560c89e9a40174eff64c51946f425fd6001))
* align the SDK with the current tamga-api server contract ([7f3ce1f](https://github.com/tamga-sh/tamga-python/commit/7f3ce1f25bccc8abdab5bcb647ac80b70d789a36))
* **ci:** run CI on stacked pull requests, not only PRs onto main ([ac9b44c](https://github.com/tamga-sh/tamga-python/commit/ac9b44c1dfea432471151d44a2b1454e87511a10))
* clamp a non-positive heartbeat interval instead of busy-looping ([0647752](https://github.com/tamga-sh/tamga-python/commit/0647752937df0e89873bb7ede1a0ec2883cb5240))
* correct the heartbeat guidance to state the rule as never stopping on any status ([f76199a](https://github.com/tamga-sh/tamga-python/commit/f76199a7d8ddc2f57e9654db9c9fd0633eb64265))
* correct the notes that said these routes were unreachable ([7cc3ed8](https://github.com/tamga-sh/tamga-python/commit/7cc3ed8a04d8fcfc28534040baf3f6157ed45c4d))
* document that the machine routes are unscoped, and three of them write ([e48e5d6](https://github.com/tamga-sh/tamga-python/commit/e48e5d677e39917ef2ffc9b77d396f40e837ff92))
* keep __version__ in sync with the released version ([b59fc2c](https://github.com/tamga-sh/tamga-python/commit/b59fc2c17c4956d7c3902a3a3f39292c8d38acd1))
* model the policy, release and health payloads the SDK could not read ([154477a](https://github.com/tamga-sh/tamga-python/commit/154477aa2b9130c977b8b7f1e7032c7eccaaf9a1))
* narrow the DEAD guidance — machine checkout does report it ([9ca9245](https://github.com/tamga-sh/tamga-python/commit/9ca9245737d5cae3ecdb5112238637277537944b))
* raise a typed MachineOverLimitError from activate_machine, keeping ValueError ([eae6130](https://github.com/tamga-sh/tamga-python/commit/eae6130c6fceb67ec01c9be8acea1bdc01ce98be))
* reach the endpoint surface the SDK was missing ([15dc82c](https://github.com/tamga-sh/tamga-python/commit/15dc82cf44fed1bc146d386e0bf966820f675405))
* reach the machine, policy, process-delete, upgrade and health routes ([f9e901e](https://github.com/tamga-sh/tamga-python/commit/f9e901e594853692f8950694886ef9fb58029721))
* read the release resource's productId, which the server camelCases ([5481166](https://github.com/tamga-sh/tamga-python/commit/5481166e63452f14c3760fd4983d0da0331859d6))
* reject a malformed verified payload instead of crashing on it ([d2b7de7](https://github.com/tamga-sh/tamga-python/commit/d2b7de7707b8d1720edd550e68b1cb7925b22c9e))
* scope fingerprint recovery to the caller's license and refuse cross-license hits ([178161a](https://github.com/tamga-sh/tamga-python/commit/178161a64bfebc6e4b96b3971c64edd80934aa2b))
* send flat request bodies to POST /components and POST /processes ([d5cb8df](https://github.com/tamga-sh/tamga-python/commit/d5cb8dfebee35080efcb958c7fc3220e364fdb89))
* send flat request bodies to POST /components and POST /processes ([2d5ec09](https://github.com/tamga-sh/tamga-python/commit/2d5ec093fe98a07d373eb6dfa98a8ee4c4ffef9b))
* verify the machine files the server actually emits ([3000f37](https://github.com/tamga-sh/tamga-python/commit/3000f373a643c7a73ed7221a1420eae9cf0b8c4e))
* verify the machine files the server actually emits ([ee4ffc1](https://github.com/tamga-sh/tamga-python/commit/ee4ffc1641a1bd9d50e57693df57ff2ccc34bf96))

## [1.0.3](https://github.com/tamga-sh/tamga-python/compare/v1.0.2...v1.0.3) (2026-08-18)


### Bug Fixes

* **ci:** keep the lockfile in step with the released version ([#19](https://github.com/tamga-sh/tamga-python/issues/19)) ([f77824b](https://github.com/tamga-sh/tamga-python/commit/f77824b51e4b3be1470738d2b372afcdb0fbe5a1))

## [1.0.2](https://github.com/tamga-sh/tamga-python/compare/v1.0.1...v1.0.2) (2026-08-18)


### Bug Fixes

* open release PRs with a GitHub App token ([#17](https://github.com/tamga-sh/tamga-python/issues/17)) ([526543a](https://github.com/tamga-sh/tamga-python/commit/526543a1b3861f1a079d408540cc5f96ce47449d))

## [1.0.1](https://github.com/tamga-sh/tamga-python/compare/v1.0.0...v1.0.1) (2026-08-18)


### Bug Fixes

* correct SDK documentation and align package metadata ([114b16d](https://github.com/tamga-sh/tamga-python/commit/114b16d985e85ed34ea82a42c5f9a9d6856b5c9f))

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
