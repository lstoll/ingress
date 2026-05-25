package main

import "fmt"

func kubernetesServiceDNS(name, namespace string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", name, namespace)
}
