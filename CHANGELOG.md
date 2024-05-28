# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## v0.3.2 (2024-05-28)

- Added a spec [PR 153](https://github.com/silversixpence-crypto/dapol/pull/153)
- Increased the length of entity ID from 256 to 512 bits [PR 162](https://github.com/silversixpence-crypto/dapol/pull/162)
- Add option to verify API to print path information [PR 163](https://github.com/silversixpence-crypto/dapol/pull/163)

## v0.3.1 (2024-01-20)

- Minor updates to the CLI [PR 154](https://github.com/silversixpence-crypto/dapol/pull/154)

## v0.3.0 (2024-01-20)

- Adjust API to read better using DapolTree instead of Accumulator [36dd58f](https://github.com/silversixpence-crypto/dapol/commit/36dd58fcd9cd2100ac7a1c4a7010faab3397770f). Also included in this change:
  - New Salt abstraction type [5c8a580](https://github.com/silversixpence-crypto/dapol/commit/5c8a580c5250a337592951234879852a8f1df285)
  - New MaxLiability abstraction type [800b0a9](https://github.com/silversixpence-crypto/dapol/commit/800b0a95b67ad7b4badf4c089b2cfc10d400283b)
  - Deserialize Salt & Secret using FromStr [169cfa5](https://github.com/silversixpence-crypto/dapol/commit/169cfa532e86e3f27d675764d8456fc3e3270564)
  - Fix bug with Bulletproofs bit length [f2a2498](https://github.com/silversixpence-crypto/dapol/commit/f2a2498120fa35ecf589f43bc660d218ae2861ad)
- Add benchmark graphs to readme [4a73d3c](https://github.com/silversixpence-crypto/dapol/commit/4a73d3cb8284f7f60659a376fa90c5714368e627)

## v0.2.0 (2023-12-27)

- Add max_thread_count API parameter [62be10c](https://github.com/silversixpence-crypto/dapol/commit/62be10c9393b2b7e2a4feeedde53fd8a793cbf30)
- Add benchmarks [8ff0379](https://github.com/silversixpence-crypto/dapol/commit/8ff037967fa536fca1122373d72e3e4acb8f169c)
- Fix bug with thread pool not being refilled [5c79aa8](https://github.com/silversixpence-crypto/dapol/commit/5c79aa86cae9b24654b8fa869a010c2edb4815bf)
- Add fuzzing tests [5c79aa8](https://github.com/silversixpence-crypto/dapol/commit/5c79aa86cae9b24654b8fa869a010c2edb4815bf)
- Add benchmark data [bb8c26d](https://github.com/silversixpence-crypto/dapol/commit/bb8c26d3fde82392334be9b39a1ab862f073f854)
- Make code adhere to Rust standards [5a16b36](https://github.com/silversixpence-crypto/dapol/commit/5a16b364771455cb5db0aa8c0ce24e0469d49521)


## v0.1.0 (2023-11-16)

Initial code publish [14fe157](https://github.com/silversixpence-crypto/dapol/commit/14fe1572430992ed0c2bc0c360dc3695f6362004)
