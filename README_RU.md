![[logo]](./assets/logo.png)

Русский | [English](./README.md)

# Проект Neutrino

Данный репозиторий относится к проекту [Neutrino](https://github.com/agnostic-t/neutrino-core), является базовой реализацией модуля `obfs`.

## Содержание

На данный момент содержит реализации:

- [xobfs](./xobfs/obfuscation.go): реализация интерфейса на основе алгоритма [xOBFS](https://github.com/agnostic-t/xobfs). Описание алгоритма можно почитать на https://docs.worldfreeteam.org
- [nobfs](./nobfs/obfuscation.go): реализация заглушки для интерфейса, не обфусцирует данные, данные никак не меняются от функций обфускации/деобфускации

Планируется добавление:

- `chacha20-AEAD`: использование ChaCha20 алгоритма для шифрования трафика
