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
| :warning: am sleepy as hell. will elaborate on them in near future :warning: |
| :---: |