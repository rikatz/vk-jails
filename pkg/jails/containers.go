package jails

import (
	"context"
	"io"
	"io/ioutil"
	"strings"

	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
)

// GetContainerLogs retrieves the logs of a container by name from the provider.
// TODO: Implement the Log reader for Jails
func (p *JailsProvider) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts api.ContainerLogOpts) (io.ReadCloser, error) {

	log.G(ctx).Infof("receive GetContainerLogs %q", podName)
	return ioutil.NopCloser(strings.NewReader("")), nil
}

// RunInContainer executes a command in a container in the pod, copying data
// between in/out/err and the container's stdin/stdout/stderr.
// TODO: Implement
func (p *JailsProvider) RunInContainer(ctx context.Context, namespace, name, container string, cmd []string, attach api.AttachIO) error {
	log.G(context.TODO()).Infof("receive ExecInContainer %q", container)
	return nil
}
