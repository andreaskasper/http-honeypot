# http-honeypot
A simple web hionepot to capture typical hacking web requests and answer with mock answers. It created a fake WebServer which answers very very very sloooooowwww. It keeps WebCclients locked up for hours or even days at a time. The purpose is to put your real Web server on another port and then let the script kiddies get stuck in this tarpit instead of bothering a real server.

### Features
- [x] Creates a simple tarpit for your WebServer

### Build status:
[![Build Status](https://img.shields.io/docker/cloud/automated/andreaskasper/http-honeypot.svg)](https://hub.docker.com/r/andreaskasper/http-honeypot)
[![Build Status](https://img.shields.io/docker/cloud/build/andreaskasper/http-honeypot.svg)](https://hub.docker.com/r/andreaskasper/http-honeypot)
![Build Status](https://img.shields.io/docker/image-size/andreaskasper/http-honeypot/latest)

### Bugs & Issues:
[![Github Issues](https://img.shields.io/github/issues/andreaskasper/http-honeypot.svg)](https://github.com/andreaskasper/http-honeypot/issues)
![Code Languages](https://img.shields.io/github/languages/top/andreaskasper/http-honeypot.svg)

### Stats:
![Docker Pulls](https://img.shields.io/docker/pulls/andreaskasper/http-honeypot.svg)

### Demo:
[![Play with docker](https://raw.githubusercontent.com/play-with-docker/stacks/cff22438cb4195ace27f9b15784bbb497047afa7/assets/images/button.png)](http://play-with-docker.com/?stack=https://raw.githubusercontent.com/andreaskasper/http-honeypot/main/stack.yml)

### Running the container :
#### Simple Run

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
| PUSHOVER_APP            |                   | The app token of your Pushover app                                           |
| PUSHOVER_NOTIFY_COUNTRY |                   | Enter the country-code of the country you wanna monitor (Example US, DE,...) |
| PUSHOVER_RECIPIENT      |                   | The user token of your Pushover account, which should receive notifications  |



### Steps
- [x] Build a base test image to test this build process (Travis/Docker)
- [ ] Build tests
- [ ] Gnomes
- [ ] Profit

### support the projects :hammer_and_wrench:
[![donate via Patreon](https://img.shields.io/badge/Donate-Patreon-green.svg)](https://www.patreon.com/AndreasKasper)
[![donate via PayPal](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/AndreasKasper)
[![donate via Bitcoin](https://img.shields.io/badge/Bitcoin-35pBJSdu7DJJPyX6Mnz57aQ68uL89yL7ga-brightgreen.png)](bitcoin:35pBJSdu7DJJPyX6Mnz57aQ68uL89yL7ga?label=github-http-honeypot)
