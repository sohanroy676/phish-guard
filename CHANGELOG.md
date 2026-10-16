# Changelog

All notable changes to this project are documented here.
Format follows Keep a Changelog. Generated from Conventional Commits — regenerate via the `/commit` command, do not hand-edit.

## [Unreleased]

### Bug Fixes

* **ci:** fetch full history so gitleaks can scan PR commits ([3dbb5cd](https://github.com/sohanroy676/phish-guard/commit/3dbb5cd7df2b1d274362efefaae0404912c2f06e))
* **ci:** install the phishguard package before running tests ([a2c731e](https://github.com/sohanroy676/phish-guard/commit/a2c731eb087061f8747ba1fb0d23c959937f4909))
* **ci:** pass GITHUB_TOKEN to the gitleaks scan ([a35ca16](https://github.com/sohanroy676/phish-guard/commit/a35ca16f33edd05ea31503267fa565145e0488ab))
* **url:** report unsupported schemes as http/https only ([9768bff](https://github.com/sohanroy676/phish-guard/commit/9768bff4d177b5794a467f171912bc2448a1aa0b))


### Features

* **app:** add accounts and POST /api/analyze/url ([2150386](https://github.com/sohanroy676/phish-guard/commit/2150386588b0ab7147671c2cb712607cddc198b0))
* **core:** add risk bands, model reasons and URL scorer ([87e9f64](https://github.com/sohanroy676/phish-guard/commit/87e9f64fc48e0a843582db97521a1858c930549e))
* **skeleton:** add v0.1.0 backend, web shell and tooling ([fe94366](https://github.com/sohanroy676/phish-guard/commit/fe94366efe2641ca5839a5aa07debfa65941d299))
* **training:** choose t_low by a false-positive cap ([36b6443](https://github.com/sohanroy676/phish-guard/commit/36b64438111a61140f467e7515512c7a9f2a9bd4))
* **url-core:** add URL normalize, features and rules ([62c5c5c](https://github.com/sohanroy676/phish-guard/commit/62c5c5ccf13e04f129ef619c2801a38656aeeda1))
* **url-model:** add URL audit, split, training and evaluation ([e07c02e](https://github.com/sohanroy676/phish-guard/commit/e07c02ec0025907673b7a64e6485cc503cc02701))
* **url-model:** train on host-only inputs and record v1 results ([b340541](https://github.com/sohanroy676/phish-guard/commit/b3405416af70bd960c009191324bc37045cf4d32))
* **web:** add register, login and URL analysis pages ([9fe1e86](https://github.com/sohanroy676/phish-guard/commit/9fe1e86e2d79899fd6dd74905e7d179348918dee))
