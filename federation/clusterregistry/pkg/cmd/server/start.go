/*
Copyright 2016 The Kubernetes Authors.

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

package server

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//"k8s.io/apimachinery/pkg/version"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/client-go/pkg/version"
	"k8s.io/kube-aggregator/pkg/apiserver"
	registryapi "k8s.io/kubernetes/federation/clusterregistry/pkg/apis/registry"
	"k8s.io/kubernetes/federation/clusterregistry/pkg/apis/registry/v1alpha1"
	registryapiserver "k8s.io/kubernetes/federation/clusterregistry/pkg/apiserver"
	registryregistry "k8s.io/kubernetes/federation/clusterregistry/pkg/registry"
	clusterstorage "k8s.io/kubernetes/federation/clusterregistry/pkg/registry/registry/cluster"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	informers "k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion"
	kubeoptions "k8s.io/kubernetes/pkg/kubeapiserver/options"
	"k8s.io/kubernetes/pkg/registry/cachesize"
	"k8s.io/kubernetes/pkg/routes"
)

const defaultEtcdPathPrefix = "/registry/registry.kubernetes.io"

type RegistryServerOptions struct {
	GenericServerRunOptions *genericoptions.ServerRunOptions
	Etcd                    *genericoptions.EtcdOptions
	SecureServing           *genericoptions.SecureServingOptions
	InsecureServing         *kubeoptions.InsecureServingOptions
	Audit                   *genericoptions.AuditOptions
	Features                *genericoptions.FeatureOptions
	Admission               *genericoptions.AdmissionOptions
	Authentication          *kubeoptions.BuiltInAuthenticationOptions
	Authorization           *kubeoptions.BuiltInAuthorizationOptions
	CloudProvider           *kubeoptions.CloudProviderOptions
	StorageSerialization    *kubeoptions.StorageSerializationOptions
	APIEnablement           *kubeoptions.APIEnablementOptions

	EventTTL time.Duration

	StdOut io.Writer
	StdErr io.Writer
}

// NewRegistryServerOptions creates a new RegistryServerOptions object with default values.
func NewRegistryServerOptions(out, errOut io.Writer) *RegistryServerOptions {
	s := RegistryServerOptions{
		GenericServerRunOptions: genericoptions.NewServerRunOptions(),
		Etcd:                 genericoptions.NewEtcdOptions(storagebackend.NewDefaultConfig(kubeoptions.DefaultEtcdPathPrefix, apiserver.Scheme, nil)),
		SecureServing:        kubeoptions.NewSecureServingOptions(),
		InsecureServing:      kubeoptions.NewInsecureServingOptions(),
		Audit:                genericoptions.NewAuditOptions(),
		Features:             genericoptions.NewFeatureOptions(),
		Admission:            genericoptions.NewAdmissionOptions(),
		Authentication:       kubeoptions.NewBuiltInAuthenticationOptions().WithAnyonymous(),
		Authorization:        kubeoptions.NewBuiltInAuthorizationOptions(),
		CloudProvider:        kubeoptions.NewCloudProviderOptions(),
		StorageSerialization: kubeoptions.NewStorageSerializationOptions(),
		APIEnablement:        kubeoptions.NewAPIEnablementOptions(),

		EventTTL: 1 * time.Hour,

		StdOut: out,
		StdErr: errOut,
	}
	// Overwrite the default for storage data format.
	s.Etcd.DefaultStorageMediaType = "application/vnd.kubernetes.protobuf"
	// Set the default for admission plugins names
	//s.Admission.PluginNames = []string{"AlwaysAdmit"}
	return &s
}

// AddFlags adds flags for RegistryServerOptions fields to be specified via FlagSet.
func (s *RegistryServerOptions) AddFlags(fs *pflag.FlagSet) {
	// Add the generic flags.
	s.GenericServerRunOptions.AddUniversalFlags(fs)
	s.Etcd.AddFlags(fs)
	s.SecureServing.AddFlags(fs)
	s.InsecureServing.AddFlags(fs)
	s.Audit.AddFlags(fs)
	s.Features.AddFlags(fs)
	s.Authentication.AddFlags(fs)
	s.Authorization.AddFlags(fs)
	s.CloudProvider.AddFlags(fs)
	s.StorageSerialization.AddFlags(fs)
	s.APIEnablement.AddFlags(fs)
	s.Admission.AddFlags(fs)

	fs.DurationVar(&s.EventTTL, "event-ttl", s.EventTTL,
		"Amount of time to retain events.")
}

// NewCommandStartMaster provides a CLI handler for 'start master' command
func NewCommandStartRegistryServer(out, errOut io.Writer, stopCh <-chan struct{}) *cobra.Command {
	o := NewRegistryServerOptions(out, errOut)

	cmd := &cobra.Command{
		Short: "Launch a registry API server",
		Long:  "Launch a registry API server",
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}
			if err := NonBlockingRun(o, stopCh); err != nil {
				return err
			}
			return nil
		},
	}

	flags := cmd.Flags()
	o.AddFlags(flags)

	return cmd
}

func (o *RegistryServerOptions) Validate(args []string) error {
	return nil
}

func (o *RegistryServerOptions) Complete() error {
	return nil
}

func NonBlockingRun(s *RegistryServerOptions, stopCh <-chan struct{}) error {

	// set defaults
	if err := s.GenericServerRunOptions.DefaultAdvertiseAddress(s.SecureServing); err != nil {
		return err
	}
	if err := kubeoptions.DefaultAdvertiseAddress(s.GenericServerRunOptions, s.InsecureServing); err != nil {
		return err
	}
	if err := s.SecureServing.MaybeDefaultWithSelfSignedCerts(s.GenericServerRunOptions.AdvertiseAddress.String(), nil, nil); err != nil {
		return fmt.Errorf("error creating self-signed certificates: %v", err)
	}
	if err := s.CloudProvider.DefaultExternalHost(s.GenericServerRunOptions); err != nil {
		return fmt.Errorf("error setting the external host value: %v", err)
	}
	s.SecureServing.ForceLoopbackConfigUsage()

	s.Authentication.ApplyAuthorization(s.Authorization)

	genericConfig := genericapiserver.NewConfig(apiserver.Codecs)
	if err := s.GenericServerRunOptions.ApplyTo(genericConfig); err != nil {
		return err
	}
	//insecureServingOptions, err := s.InsecureServing.ApplyTo(genericConfig)
	//if err != nil {
	//	return err
	//}
	if err := s.SecureServing.ApplyTo(genericConfig); err != nil {
		return err
	}
	if err := s.Authentication.ApplyTo(genericConfig); err != nil {
		return err
	}
	if err := s.Audit.ApplyTo(genericConfig); err != nil {
		return err
	}
	if err := s.Features.ApplyTo(genericConfig); err != nil {
		return err
	}

	if s.Etcd.StorageConfig.DeserializationCacheSize == 0 {
		// When size of cache is not explicitly set, set it to 50000
		s.Etcd.StorageConfig.DeserializationCacheSize = 50000
	}

	if err := s.Etcd.ApplyTo(genericConfig); err != nil {
		return err
	}

	apiAuthenticator /*securityDefinitions*/, _, err := s.Authentication.ToAuthenticationConfig().New()
	if err != nil {
		return fmt.Errorf("invalid Authentication Config: %v", err)
	}

	client, err := internalclientset.NewForConfig(genericConfig.LoopbackClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %v", err)
	}
	//externalClient, err := clientset.NewForConfig(genericConfig.LoopbackClientConfig)
	//if err != nil {
	//	return fmt.Errorf("failed to create external clientset: %v", err)
	//}
	sharedInformers := informers.NewSharedInformerFactory(client, 10*time.Minute)

	//authorizationConfig := s.Authorization.ToAuthorizationConfig(sharedInformers)
	//apiAuthorizer, err := authorizationConfig.New()
	//if err != nil {
	//	return fmt.Errorf("invalid Authorization Config: %v", err)
	//}

	//var cloudConfig []byte
	//if s.CloudProvider.CloudConfigFile != "" {
	//	cloudConfig, err = ioutil.ReadFile(s.CloudProvider.CloudConfigFile)
	//	if err != nil {
	//		glog.Fatalf("Error reading from cloud configuration file %s: %#v", s.CloudProvider.CloudConfigFile, err)
	//	}
	//}

	err = s.Admission.ApplyTo(
		genericConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize plugins: %v", err)
	}

	kubeVersion := version.Get()
	genericConfig.Version = &kubeVersion
	genericConfig.Authenticator = apiAuthenticator
	//	genericConfig.Authorizer = apiAuthorizer
	//	genericConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(openapi.GetOpenAPIDefinitions, apiserver.Scheme)
	//	genericConfig.OpenAPIConfig.PostProcessSpec = postProcessOpenAPISpecForBackwardCompatibility
	// genericConfig.OpenAPIConfig.SecurityDefinitions = securityDefinitions
	genericConfig.SwaggerConfig = genericapiserver.DefaultSwaggerConfig()
	//genericConfig.LongRunningFunc = filters.BasicLongRunningRequestCheck(
	//	sets.NewString("watch", "proxy"),
	//	sets.NewString("attach", "exec", "proxy", "log", "portforward"),
	//)

	// TODO: Move this to generic api server (Need to move the command line flag).
	if s.Etcd.EnableWatchCache {
		cachesize.InitializeWatchCacheSizes(s.GenericServerRunOptions.TargetRAMMB)
		cachesize.SetWatchCacheSizes(s.GenericServerRunOptions.WatchCacheSizes)
	}

	m, err := genericConfig.Complete().New("clusterregistry", genericapiserver.EmptyDelegate)
	if err != nil {
		return err
	}

	routes.UIRedirect{}.Install(m.Handler.NonGoRestfulMux)
	routes.Logs{}.Install(m.Handler.GoRestfulContainer)

	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(registryapi.GroupName, registryapiserver.Registry, registryapiserver.Scheme, metav1.ParameterCodec, apiserver.Codecs)
	apiGroupInfo.GroupMeta.GroupVersion = v1alpha1.SchemeGroupVersion
	v1alpha1storage := map[string]rest.Storage{}
	v1alpha1storage["clusters"] = registryregistry.RESTInPeace(clusterstorage.NewREST(registryapiserver.Scheme, genericConfig.RESTOptionsGetter))
	apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

	if err := m.InstallAPIGroup(&apiGroupInfo); err != nil {
		return err
	}

	// run the insecure server now
	//if insecureServingOptions != nil {
	//	insecureHandlerChain := kubeserver.BuildInsecureHandlerChain(m.UnprotectedHandler(), genericConfig)
	//	if err := kubeserver.NonBlockingRun(insecureServingOptions, insecureHandlerChain, stopCh); err != nil {
	//		return err
	//	}
	//}

	err = m.PrepareRun().NonBlockingRun(stopCh)
	if err == nil {
		sharedInformers.Start(stopCh)
	}
	return err
}

//func (o *RegistryServerOptions) Config() (*apiserver.Config, error) {
//	// TODO have a "real" external address
//	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("35.197.127.188", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
//		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
//	}
//
//	serverConfig := genericapiserver.NewConfig(apiserver.Codecs)
//	if err := o.RecommendedOptions.ApplyTo(serverConfig); err != nil {
//		return nil, err
//	}
//
//	if err := o.Admission.ApplyTo(serverConfig); err != nil {
//		return nil, err
//	}
//
//	config := &apiserver.Config{
//		GenericConfig: serverConfig,
//	}
//	return config, nil
//}
//
//func (o RegistryServerOptions) RunRegistryServer(stopCh <-chan struct{}) error {
//	config, err := o.Config()
//	if err != nil {
//		return err
//	}
//
//	server, err := config.Complete().New()
//	if err != nil {
//		return err
//	}
//	return server.GenericAPIServer.PrepareRun().Run(stopCh)
//}
