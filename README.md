![[logo]](./assets/logo.png)

English | [Русский](./README_RU.md)

# Neutrino Project

This repository belongs to the [Neutrino](https://github.com/agnostic-t/neutrino-core) project and is the base implementation of the `obfs` module.

## Contents

Currently contains the following implementations:

- [xobfs](./xobfs/obfuscation.go): an interface implementation based on the [xOBFS](https://github.com/agnostic-t/xobfs) algorithm. A description of the algorithm can be found at https://docs.worldfreeteam.org
- [nobfs](./nobfs/obfuscation.go): a stub implementation for the interface; does not obfuscate data; data is not affected by obfuscation/deobfuscation functions.

Planned additions:

- `chacha20-AEAD`: use of the ChaCha20 algorithm for traffic encryption
