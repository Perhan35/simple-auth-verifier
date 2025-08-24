### Building and running your application

When you're ready, start your application by running:
`docker compose up --build`.

Your application will be available at http://localhost:8000.

### Deploying your application to the cloud

First, build your image, e.g.: 
SLIM
```shell
docker build -f Dockerfile-slim --platform linux/amd64,linux/arm64/v8 -t simple-auth-verifier:slim .
```
ALPINE
```shell
docker build -f Dockerfile-alpine --platform linux/amd64,linux/arm64/v8 -t simple-auth-verifier:alpine .
```

Then, push it to your registry, e.g. 
```shell
docker push simple-auth-verifier:slim
docker push simple-auth-verifier:alpine
```

Or, all at once:
```bash
for tag in alpine slim; do
  docker build -f Dockerfile-$tag -t --platform linux/amd64,linux/arm64/v8 -t simple-auth-verifier::$tag .
  docker push simple-auth-verifier:$tag
done
```

Consult Docker's [getting started](https://docs.docker.com/go/get-started-sharing/)
docs for more detail on building and pushing.

### References
* [Docker's Node.js guide](https://docs.docker.com/language/nodejs/)