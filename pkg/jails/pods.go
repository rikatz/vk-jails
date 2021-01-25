package jails

import (
	"context"
	"fmt"
	"time"

	"github.com/virtual-kubelet/virtual-kubelet/errdefs"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gojail "purplekraken.com/pkg/gojail"
)

// CreatePod accepts a Pod definition and stores it in memory.
func (p *JailsProvider) CreatePod(ctx context.Context, pod *v1.Pod) error {

	log.G(ctx).Infof("received CreatePod %q", pod.Name)

	// TODO: Should clarify the need of buildKey
	key, err := buildKey(pod)
	if err != nil {
		return err
	}

	now := metav1.NewTime(time.Now())

	jailParams := []gojail.JailParam{}
	// TODO: This probably needs to be a hash, once we call a Jail a container and not a Pod.
	// Later we can make multiple jails share the same network, maybe :)
	name, err := gojail.NewStringParam("name", string(pod.UID))
	if err != nil {
		// TODO: Maybe because of the repetition of this, we can create a helper func
		return fmt.Errorf("Failed to create the Pod name param. Pod: %s Error: %s", string(pod.UID), err)
	}

	hostname, err := gojail.NewStringParam("host.hostname", key)
	if err != nil {
		return fmt.Errorf("Failed to create the Pod hostname param. Pod: %s Error: %s", string(pod.UID), err)
	}

	// TODO: Remove the hardcoded path to something better.
	// Here, we need to create a path for each new Pod, with a copy of the
	// base FreeBSD image, and remove it once the Pod gets destroyed.
	// Hard part here :D
	path, err := gojail.NewStringParam("path", "/jails/katz")
	if err != nil {
		return fmt.Errorf("Failed to create the Pod path param. Pod: %s Error: %s", string(pod.UID), err)
	}

	// We should persist, otherwise we should attach
	persist, err := gojail.NewStringParam("persist", "")
	if err != nil {
		return fmt.Errorf("Failed to create the Pod persist param. Pod: %s Error: %s", string(pod.UID), err)
	}

	// TODO: Change the securelevel based on Privileged Containers
	/*	if pod.Spec.Containers[0].SecurityContext.Privileged != nil && *pod.Spec.Containers[0].SecurityContext.Privileged {
		jail.Params["securelevel"] = "0"
	}*/
	securelevel, err := gojail.NewIntParam("securelevel", 3)
	if err != nil {
		return fmt.Errorf("Failed to create the Pod securelevel param. Pod: %s Error: %s", string(pod.UID), err)
	}

	// TODO: Get an IP address from CNI binary here
	podIP := "192.168.0.244"
	ip4, err := gojail.NewIPParam(podIP)
	if err != nil {
		return fmt.Errorf("Failed to create the Pod IPv4 param. Pod: %s Error: %s", string(pod.UID), err)
	}

	jailParams = append(jailParams, name, hostname, path, persist, securelevel, ip4)

	jid, err := gojail.SetParams(jailParams, gojail.CreateFlag)

	if err != nil {
		return fmt.Errorf("Failed to create the Pod: %s", err)
	}

	pod.Status = v1.PodStatus{
		Phase:     v1.PodRunning,
		HostIP:    p.internalIP,
		PodIP:     podIP,
		StartTime: &now,
		Conditions: []v1.PodCondition{
			{
				Type:   v1.PodInitialized,
				Status: v1.ConditionTrue,
			},
			{
				Type:   v1.PodReady,
				Status: v1.ConditionTrue,
			},
			{
				Type:   v1.PodScheduled,
				Status: v1.ConditionTrue,
			},
		},
	}
	containerName := fmt.Sprintf("%s-%d", key, jid)
	for _, container := range pod.Spec.Containers {
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, v1.ContainerStatus{
			Name:         containerName,
			Image:        container.Image,
			Ready:        true,
			RestartCount: 0,
			State: v1.ContainerState{
				Running: &v1.ContainerStateRunning{
					StartedAt: now,
				},
			},
		})
	}

	p.pods[key] = pod
	p.notifier(pod)

	return nil
}

// UpdatePod accepts a Pod definition and updates its reference.
// TODO: Implement the UpdatePod here
func (p *JailsProvider) UpdatePod(ctx context.Context, pod *v1.Pod) error {

	log.G(ctx).Infof("receive UpdatePod %q", pod.Name)

	key, err := buildKey(pod)
	if err != nil {
		return err
	}

	p.pods[key] = pod
	p.notifier(pod)

	return nil
}

// DeletePod deletes the specified pod out of memory.
func (p *JailsProvider) DeletePod(ctx context.Context, pod *v1.Pod) (err error) {

	/* Description of what we should do here:
	1) Stop / delete the jails of the Pod (now it's only one)
	2) Remove the IP from the main interface (or when we use VNET in future, destroy it)
	3) Remove the ZFS Snapshot generated to this Pod / unmount / etc
	*/
	log.G(ctx).Infof("receive DeletePod %q", pod.Name)

	key, err := buildKey(pod)
	if err != nil {
		return err
	}

	if _, exists := p.pods[key]; !exists {
		return errdefs.NotFound("pod not found")
	}

	now := metav1.Now()

	jid, err := gojail.GetId(string(pod.UID))
	if err != nil {
		return fmt.Errorf("Failed to delete the Pod %s Failed to get Jail ID, Error: %s", string(pod.UID), err)
	}

	err := gojail.Remove(jid)
	if err != nil {
		return fmt.Errorf("Failed to delete the Pod %s Error: %s", string(pod.UID), err)
	}

	delete(p.pods, key)
	pod.Status.Phase = v1.PodSucceeded
	pod.Status.Reason = "JailProviderPodDeleted"

	for idx := range pod.Status.ContainerStatuses {
		pod.Status.ContainerStatuses[idx].Ready = false
		pod.Status.ContainerStatuses[idx].State = v1.ContainerState{
			Terminated: &v1.ContainerStateTerminated{
				Message:    "Jail provider terminated container upon deletion",
				FinishedAt: now,
				Reason:     "JailProviderPodContainerDeleted",
				StartedAt:  pod.Status.ContainerStatuses[idx].State.Running.StartedAt,
			},
		}
	}

	p.notifier(pod)

	return nil
}

// GetPod returns a pod by name
// TODO: We need to provide a better way to store which Pods/Jails are
// already running on the vk-jails, instead of storing them in memory.
// If the vk-jails binary restarts, it's not going to be aware of the Pods
// it contains
func (p *JailsProvider) GetPod(ctx context.Context, namespace, name string) (pod *v1.Pod, err error) {

	log.G(ctx).Infof("receive GetPod %q", name)

	key, err := buildKeyFromNames(namespace, name)
	if err != nil {
		return nil, err
	}

	if pod, ok := p.pods[key]; ok {
		return pod, nil
	}
	return nil, errdefs.NotFoundf("pod \"%s/%s\" is not known to the provider", namespace, name)
}

// GetPodStatus returns the status of a pod by name that is "running".
// returns nil if a pod by that name is not found.
func (p *JailsProvider) GetPodStatus(ctx context.Context, namespace, name string) (*v1.PodStatus, error) {

	log.G(ctx).Infof("receive GetPodStatus %q", name)

	pod, err := p.GetPod(ctx, namespace, name)
	if err != nil {
		return nil, err
	}

	return &pod.Status, nil
}

// GetPods returns a list of all pods known to be "running".
func (p *JailsProvider) GetPods(ctx context.Context) ([]*v1.Pod, error) {

	log.G(ctx).Info("receive GetPods")

	var pods []*v1.Pod

	for _, pod := range p.pods {
		pods = append(pods, pod)
	}

	return pods, nil
}

// NotifyPods is called to set a pod notifier callback function. This should be called before any operations are done
// within the provider.
func (p *JailsProvider) NotifyPods(ctx context.Context, notifier func(*v1.Pod)) {
	p.notifier = notifier
}

func buildKeyFromNames(namespace string, name string) (string, error) {
	return fmt.Sprintf("%s-%s", namespace, name), nil
}

// buildKey is a helper for building the "key" for the providers pod store.
func buildKey(pod *v1.Pod) (string, error) {
	if pod.ObjectMeta.Namespace == "" {
		return "", fmt.Errorf("pod namespace not found")
	}

	if pod.ObjectMeta.Name == "" {
		return "", fmt.Errorf("pod name not found")
	}

	return buildKeyFromNames(pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
}
