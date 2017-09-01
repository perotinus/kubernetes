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

package cluster

import (
	"fmt"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"

	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	registryapi "k8s.io/kubernetes/federation/clusterregistry/pkg/apis/registry"
)

func NewStrategy(typer runtime.ObjectTyper) clusterStrategy {
	return clusterStrategy{typer, names.SimpleNameGenerator}
}

func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, bool, error) {
	apiserver, ok := obj.(*registryapi.Cluster)
	if !ok {
		return nil, nil, false, fmt.Errorf("given object is not a Cluster.")
	}
	return labels.Set(apiserver.ObjectMeta.Labels), clusterToSelectableFields(apiserver), apiserver.Initializers != nil, nil
}

// MatchCluster is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchCluster(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: GetAttrs,
	}
}

// clusterToSelectableFields returns a field set that represents the object.
func clusterToSelectableFields(obj *registryapi.Cluster) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type clusterStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

func (clusterStrategy) NamespaceScoped() bool {
	return false
}

func (clusterStrategy) PrepareForCreate(ctx genericapirequest.Context, obj runtime.Object) {
}

func (clusterStrategy) PrepareForUpdate(ctx genericapirequest.Context, obj, old runtime.Object) {
}

func (clusterStrategy) Validate(ctx genericapirequest.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (clusterStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (clusterStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (clusterStrategy) Canonicalize(obj runtime.Object) {
}

func (clusterStrategy) ValidateUpdate(ctx genericapirequest.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}
