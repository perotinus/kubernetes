/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package registry

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ClusterList is a list of Cluster objects.
type ClusterList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Cluster
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Cluster struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	KubeAPIServer KubeAPIServer
	AuthInfo      AuthInfo
	CloudProvider CloudProvider
}

type KubeAPIServer struct {
	// Server specifies the address of the Kubernetes cluster endpoint.
	// It can be an any valid HTTP URL including the IP:Port combination
	// or the host name.
	Server URL
}

type AuthInfo struct {
	// TBD
}

type CloudProvider struct {
	Name string
}

type URL string
