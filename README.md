[![Go Report](https://goreportcard.com/badge/github.com/BerlingskeMedia/drone-standalone-task)](https://goreportcard.com/report/github.com/BerlingskeMedia/drone-standalone-task)


# drone-scheduled-tasks

This plugin was created on base of Josmo's drone-ecs plugin. In fact it is modified version, which runs only standalone tasks instead of whole services. Big thanks for his work!

Drone plugin to run standalone tasks in AWS ECS. For the usage information and a listing of the available options please take a look at [the docs](DOCS.md).

## Binary

Build the binary using `drone cli`:

```
drone exec
```

### Example

```
docker run --rm                          \
  -e PLUGIN_ACCESS_KEY=<key>             \
  -e PLUGIN_SECRET_KEY=<secret>          \
  -e PLUGIN_SERVICE=<service>            \  
  -e PLUGIN_DOCKER_IMAGE=<image>         \
  -v $(pwd):$(pwd)                       \
  -w $(pwd)                              \
  pelotech/drone-ecs
```

### Contribution

This repo is setup in a way that if you enable a personal drone server to build your fork it will
 build and publish your image (makes it easier to test PRs and use the image till the contributions get merged)
 
* Build local ```DRONE_REPO_OWNER=BerlingskeMedia DRONE_REPO_NAME=drone-ecs drone exec```
* on your server just make sure you have DOCKER_USERNAME, DOCKER_PASSWORD, and PLUGIN_REPO set as secrets
