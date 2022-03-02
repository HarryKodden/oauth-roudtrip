# Readme...

This repository demonstrates the complete **OAUTH** roundtrip:
- Client authenticating at **Issuer Server**
- Upon succesful authentication, the clients obtains an **Access-Token**
- Usingf that **Access-Token** the Client request for a service from a **Resource Server**.
- The **Resource Server** verifies the validity of the **Access-Token** by interacting with the **Issuer Server** and upon success returns service response.

## Prerequisites:
- docker
- docker-compose
- copy *.env.sample* to *.env* and adjust whatever you like better
- create entry in */etc/hosts* file (if not exists):

```
127.0.0.1  host.docker.internal
```

## Run on localhost:
* docker-compose build
* docker-compose run
* (optional) docker-compose logs -f
* Start demonstration at by opening browser session: http://localhost:5000
  

### Credits
- https://github.com/michaelawyu/auth-server-sample/commits?author=michaelawyu
- https://medium.com/@ratrosy/building-a-basic-authorization-server-using-authorization-code-flow-c06866859fb1

