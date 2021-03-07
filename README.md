# CloudFormation drive for Docker Machine, for gitlab-runners

This docker-machine driver accepts a CloudFormation stack and expects a Spot
Fleet output. The instance from this spot fleet is then given back to
`docker-machine`.

The main use-case is to be used with `docker-machine` executor for GitLab
runners.

This is based on the more general and great `docker-machine-driver-terraform`
project. This project works very well if you want to use terraform to manage the
resources. Sadly, for us, we often wanted to spawn many different resource
stacks at once and using `terraform` for this heavily overwhelmed the EC2
instance we were using.

The main idea behind _this_ project is that we let AWS do all the heavy work and
we only do light weight API queries, checking if it's done. We force the user to
provision heavy resources like SSH keys up front and don't rely on things being
on the local file system.
