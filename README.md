# Wooting Wootility Protocol

## Introduction

Wooting has been very generous in supplying Open Source (!) SDKs for their hardware, only, the SDKs aren't
very thoroughly documented, limited to a single use case and written in C.

This repository tries to fill in these gaps, it generated the packets and the used fields are described. It also
describes what the packets do and in what order they should be sent.

## Features

- Technical documentation
- Command line interface (libwootility-cli) for sending packets to the keyboard
- Unit tests

## Limitations

- Linux only (for now)
- Wooting 60HE (ARM) only, though the packets should be compatible with other keyboards.

## Installation

Run:

```bash
pipx install libwootility
```
