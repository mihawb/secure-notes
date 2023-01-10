# secure-notes

Create and share safely encrypted notes styled with markdown!

## Installation

### Build Docker image from Dockerfile
Standing in repository root build image.
```
docker build -t mihawb/secure-notes .
```
Use the image to create a container. **Remember to map exposed ports!**
```
 docker run -d --name secure-notes-app -p 80:80 -p 443:443 mihawb/secure-notes
```
Go to [`localhost`](https://localhost) and take some notes!

### Pull image from Docker Hub
Pull the latest tag of the prebuild image available [here](https://hub.docker.com/r/mihawb/secure-notes/tags).
```
docker pull mihawb/secure-notes:latest
```
Create a container in the same manner as shown above.

## Key features
* Notes have full markdown support, as well as Notion-style banners
* Notes can be made publicly available to other registered users by sharing a link
* [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), a symmetric encryption algorithm in [block chaining mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation), is used to ensure your private notes stay private no matter what
* [Argon2](https://github.com/p-h-c/phc-winner-argon2), a modern [award-winning](https://www.password-hashing.net/) asymmetric algorithm is used to hash users' passwords and note passphrases 
* Password reset links sent by email are available to registered users. Time limit and MD5 checksums were incorporated so as to make impersonation attacks borderline impossible
* Bad requests to all endpoints have delayed response time as means of brute-force attacks prevention
* All user inputs are validated and bleached in order to prevent all kinds of injection attacks

### Resilience and security
*secure-notes* app has been tested against and proven to be resilient to many attack types, including:
* brute-force password cracking and endpoint crawling
* SSRF - server-side request forgery
* XSS - cross-site scripting	
* SQL injections
* path traversal
* null byte (and other control characters) poisoning