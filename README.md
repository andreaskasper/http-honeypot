# HTTP Honeypot
A simple web honeypot designed to capture typical hacking web requests and respond with mock answers. This project creates a fake web server that deliberately replies very, very sloooooowwwwwly, effectively locking up malicious web clients for extended periods—hours or even days. The idea is to place your real web server on a different port, letting this honeypot keep script kiddies busy while leaving your actual server undisturbed.

---

## Features
- 🌐 Provides a tarpit for would-be attackers.
- 🛡️ Protects your real web server by acting as a decoy.
- 🕒 Responds intentionally slowly to keep attackers locked in.

---

## Build Status
[![Automated Build](https://img.shields.io/docker/cloud/automated/andreaskasper/http-honeypot.svg)](https://hub.docker.com/r/andreaskasper/http-honeypot)  
[![Build Status](https://img.shields.io/docker/cloud/build/andreaskasper/http-honeypot.svg)](https://hub.docker.com/r/andreaskasper/http-honeypot)  
![Image Size](https://img.shields.io/docker/image-size/andreaskasper/http-honeypot/latest)

---

## Issues and Languages
[![GitHub Issues](https://img.shields.io/github/issues/andreaskasper/http-honeypot.svg)](https://github.com/andreaskasper/http-honeypot/issues)  
![Top Language](https://img.shields.io/github/languages/top/andreaskasper/http-honeypot.svg)

---

## Docker Pull Stats
![Docker Pulls](https://img.shields.io/docker/pulls/andreaskasper/http-honeypot.svg)

---

## Demo
[![Play with Docker](https://raw.githubusercontent.com/play-with-docker/stacks/cff22438cb4195ace27f9b15784bbb497047afa7/assets/images/button.png)](http://play-with-docker.com/?stack=https://raw.githubusercontent.com/andreaskasper/http-honeypot/main/stack.yml)

---

## Getting Started
### Quick Start
Run the honeypot using Docker with the following command:

```sh
$ docker run -p 8080:80 andreaskasper/http-honeypot
```

#### Getting help


### Environment Parameters
| Parameter               | Default           | Description                                                                  |
| ----------------------- |:-----------------:|:---------------------------------------------------------------------------- |
| METRICS_PASSWORD        | admin             | Username for your prometheus metrics                                         |
| METRICS_REALM           | Prometheus Server | Realm Name of your Prometheus Metrics                                        |
| METRICS_USER            | password          | Password for your prometheus metrics                                         |
| NAME                    |                   | Name of the Honeypot if you run more than one :-)                            |
| PUSHOVER_APP            |                   | The app token of your Pushover app                                           |
| PUSHOVER_NOTIFY_COUNTRY |                   | Enter the country-code of the country you wanna monitor (Example US, DE,...) |
| PUSHOVER_RECIPIENT      |                   | The user token of your Pushover account, which should receive notifications  |



### Development Roadmap
- ✅ Base Image: Create a test image for build process validation (Travis/Docker).
- 🔄 Tests: Implement automated tests.
- 🚧 Gnomes: (Placeholder for further development).
- 💰 Profit: Reap the benefits of a secure and engaging honeypot!

### support the projects :hammer_and_wrench:
[![donate via Patreon](https://img.shields.io/badge/Donate-Patreon-green.svg)](https://www.patreon.com/AndreasKasper)
[![donate via PayPal](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/AndreasKasper)
[![donate via Ko-fi](https://img.shields.io/badge/Donate-Ko--fi-green.svg)](https://ko-fi.com/andreaskasper)
[![donate via Bitcoin](https://img.shields.io/badge/Bitcoin-35pBJSdu7DJJPyX6Mnz57aQ68uL89yL7ga-brightgreen.png)](bitcoin:35pBJSdu7DJJPyX6Mnz57aQ68uL89yL7ga?label=github-http-honeypot)
[![Sponsors](https://img.shields.io/github/sponsors/andreaskasper)](https://github.com/sponsors/andreaskasper)
