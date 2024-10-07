// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kubestatemetrics

import (
	"context"
	"fmt"
	"time"

	"github.com/Masterminds/semver/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/component"
	operatorclient "github.com/gardener/gardener/pkg/operator/client"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
)

const (
	managedResourceName      = "kube-state-metrics"
	managedResourceNameShoot = "shoot-core-" + managedResourceName

	containerName = "kube-state-metrics"

	labelKeyComponent   = "component"
	labelKeyType        = "type"
	labelValueComponent = "kube-state-metrics"

	port            = 8080
	portNameMetrics = "metrics"

	// SuffixSeed is the suffix for seed kube-state-metrics resources.
	SuffixSeed = "-seed"
	// SuffixRuntime is the suffix for garden-runtime kube-state-metrics resources.
	SuffixRuntime = "-runtime"
	// SuffixVirtual is the suffix for the kube-state-metrics resources to monitor the virtual cluster.
	SuffixVirtual = "-virtual"
)

// New creates a new instance of DeployWaiter for the kube-state-metrics.
func New(
	client client.Client,
	namespace string,
	secretsManager secretsmanager.Interface,
	values Values,
) component.DeployWaiter {
	return &kubeStateMetrics{
		client:         client,
		secretsManager: secretsManager,
		namespace:      namespace,
		values:         values,
	}
}

type kubeStateMetrics struct {
	client         client.Client
	secretsManager secretsmanager.Interface
	namespace      string
	values         Values
}

// Values is a set of configuration values for the kube-state-metrics.
type Values struct {
	// ClusterType specifies the type of the cluster to which kube-state-metrics is being deployed.
	ClusterType component.ClusterType
	// KubernetesVersion is the Kubernetes version of the cluster.
	KubernetesVersion *semver.Version
	// Image is the container image.
	Image string
	// PriorityClassName is the name of the priority class.
	PriorityClassName string
	// Replicas is the number of replicas.
	Replicas int32
	// NameSuffix is attached to the deployment name and related resources.
	NameSuffix string
}

func (k *kubeStateMetrics) getResourcesForSeed() ([]client.Object, error) {
	customResourceStateConfigMap, err := k.customResourceStateConfigMap()
	if err != nil {
		return nil, err
	}

	var (
		clusterRole    = k.clusterRole(WithDefaultRules(), WithHorizontalPodAutoscalerRules())
		serviceAccount = k.serviceAccount()
		deployment     = k.deployment(serviceAccount, "", nil, customResourceStateConfigMap.Name)
		resources      = []client.Object{
			clusterRole,
			serviceAccount,
			k.clusterRoleBinding(clusterRole, serviceAccount),
			deployment,
			k.podDisruptionBudget(deployment),
			k.service(),
			k.verticalPodAutoscaler(deployment),
			customResourceStateConfigMap,
			k.scrapeConfigSeed(),
			k.scrapeConfigCache(),
		}
	)

	return resources, nil
}

func (k *kubeStateMetrics) getResourcesForRuntime() ([]client.Object, error) {
	customResourceStateConfigMap, err := k.customResourceStateConfigMap()
	if err != nil {
		return nil, err
	}

	var (
		clusterRole    = k.clusterRole(WithDefaultRules(), WithGardenerOperatorRules(), WithHorizontalPodAutoscalerRules())
		serviceAccount = k.serviceAccount()
		deployment     = k.deployment(serviceAccount, "", nil, customResourceStateConfigMap.Name)
		resources      = []client.Object{
			clusterRole,
			serviceAccount,
			k.clusterRoleBinding(clusterRole, serviceAccount),
			deployment,
			k.podDisruptionBudget(deployment),
			k.service(),
			k.verticalPodAutoscaler(deployment),
			customResourceStateConfigMap,
			k.scrapeConfigGarden(),
		}
	)

	return resources, nil
}

func (k *kubeStateMetrics) getResourcesForShoot(genericTokenKubeconfigSecretName string, shootAccessSecret *gardenerutils.AccessSecret) ([]client.Object, error) {
	customResourceStateConfigMap, err := k.customResourceStateConfigMap()
	if err != nil {
		return nil, err
	}

	deployment := k.deployment(nil, genericTokenKubeconfigSecretName, shootAccessSecret, customResourceStateConfigMap.Name)
	return []client.Object{
		deployment,
		k.prometheusRuleShoot(),
		k.scrapeConfigShoot(),
		k.service(),
		k.verticalPodAutoscaler(deployment),
		customResourceStateConfigMap,
	}, nil
}

func (k *kubeStateMetrics) getResourcesForShootTarget(shootAccessSecret *gardenerutils.AccessSecret) []client.Object {
	clusterRole := k.clusterRole(WithDefaultRules())
	return []client.Object{
		clusterRole,
		k.clusterRoleBinding(clusterRole, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      shootAccessSecret.ServiceAccountName,
				Namespace: metav1.NamespaceSystem,
			},
		}),
	}
}

func (k *kubeStateMetrics) getResourcesForVirtual(genericTokenKubeconfigSecretName string, shootAccessSecret *gardenerutils.AccessSecret) ([]client.Object, error) {
	customResourceStateConfigMap, err := k.customResourceStateConfigMap()
	if err != nil {
		return nil, err
	}

	deployment := k.deployment(nil, genericTokenKubeconfigSecretName, shootAccessSecret, customResourceStateConfigMap.Name)
	return []client.Object{
		deployment,
		k.scrapeConfigShoot(),
		k.podDisruptionBudget(deployment),
		k.service(),
		k.verticalPodAutoscaler(deployment),
		customResourceStateConfigMap,
		k.scrapeConfigVirtual(),
	}, nil
}

func (k *kubeStateMetrics) getResourcesForVirtualTarget(shootAccessSecret *gardenerutils.AccessSecret) []client.Object {
	clusterRole := k.clusterRole(WithGardenerVirtualClusterRules())
	return []client.Object{
		clusterRole,
		k.clusterRoleBinding(clusterRole, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      shootAccessSecret.ServiceAccountName,
				Namespace: metav1.NamespaceSystem,
			},
		}),
	}
}

func (k *kubeStateMetrics) Deploy(ctx context.Context) error {
	if k.values.ClusterType == component.ClusterTypeShoot {
		return k.deployShoot(ctx)
	}

	if k.values.ClusterType == component.ClusterTypeSeed && k.values.NameSuffix == SuffixSeed {
		return k.deploySeed(ctx)
	}

	if k.values.ClusterType == component.ClusterTypeSeed && k.values.NameSuffix == SuffixRuntime {
		return k.deployRuntime(ctx)
	}

	if k.values.ClusterType == component.ClusterTypeSeed && k.values.NameSuffix == SuffixVirtual {
		return k.deployVirtual(ctx)
	}

	return fmt.Errorf("invalid combination of cluster type %v and name suffix %v", k.values.ClusterType, k.values.NameSuffix)
}

func (k *kubeStateMetrics) deployRuntime(ctx context.Context) error {
	registry := managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)

	resources, err := k.getResourcesForRuntime()
	if err != nil {
		return err
	}

	if err := registry.Add(resources...); err != nil {
		return err
	}

	serializedResources, err := registry.SerializedObjects()
	if err != nil {
		return err
	}

	return managedresources.CreateForSeedWithLabels(
		ctx,
		k.client,
		k.namespace,
		k.managedResourceName(),
		false,
		map[string]string{v1beta1constants.LabelCareConditionType: v1beta1constants.ObservabilityComponentsHealthy},
		serializedResources,
	)
}

func (k *kubeStateMetrics) deploySeed(ctx context.Context) error {
	registry := managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)

	resources, err := k.getResourcesForSeed()
	if err != nil {
		return err
	}

	if err := registry.Add(resources...); err != nil {
		return err
	}

	serializedResources, err := registry.SerializedObjects()
	if err != nil {
		return err
	}

	return managedresources.CreateForSeedWithLabels(
		ctx,
		k.client,
		k.namespace,
		k.managedResourceName(),
		false,
		map[string]string{v1beta1constants.LabelCareConditionType: v1beta1constants.ObservabilityComponentsHealthy},
		serializedResources,
	)
}

func (k *kubeStateMetrics) deployShoot(ctx context.Context) error {
	registry := managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)
	shootAccessSecret := k.newShootAccessSecret()

	genericTokenKubeconfigSecret, found := k.secretsManager.Get(v1beta1constants.SecretNameGenericTokenKubeconfig)
	if !found {
		return fmt.Errorf("secret %q not found", v1beta1constants.SecretNameGenericTokenKubeconfig)
	}

	if err := shootAccessSecret.Reconcile(ctx, k.client); err != nil {
		return err
	}

	resources, err := k.getResourcesForShoot(genericTokenKubeconfigSecret.Name, shootAccessSecret)
	if err != nil {
		return err
	}

	if err := registry.Add(resources...); err != nil {
		return err
	}

	serializedResources, err := registry.SerializedObjects()
	if err != nil {
		return err
	}

	if err := managedresources.CreateForSeedWithLabels(
		ctx,
		k.client,
		k.namespace,
		k.managedResourceName(),
		false,
		map[string]string{v1beta1constants.LabelCareConditionType: v1beta1constants.ObservabilityComponentsHealthy},
		serializedResources,
	); err != nil {
		return err
	}

	registryTarget := managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer)
	resourcesTarget, err := registryTarget.AddAllAndSerialize(k.getResourcesForShootTarget(shootAccessSecret)...)
	if err != nil {
		return err
	}

	return managedresources.CreateForShootWithLabels(
		ctx,
		k.client,
		k.namespace,
		k.managedResourceName()+"-target",
		managedresources.LabelValueGardener,
		false,
		map[string]string{v1beta1constants.LabelCareConditionType: v1beta1constants.ObservabilityComponentsHealthy},
		resourcesTarget,
	)
}

func (k *kubeStateMetrics) deployVirtual(ctx context.Context) error {
	registry := managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)
	virtualAccessSecret := k.newShootAccessSecret()

	genericTokenKubeconfigSecret, found := k.secretsManager.Get(v1beta1constants.SecretNameGenericTokenKubeconfig)
	if !found {
		return fmt.Errorf("secret %q not found", v1beta1constants.SecretNameGenericTokenKubeconfig)
	}

	if err := virtualAccessSecret.Reconcile(ctx, k.client); err != nil {
		return err
	}

	resources, err := k.getResourcesForVirtual(genericTokenKubeconfigSecret.Name, virtualAccessSecret)
	if err != nil {
		return err
	}

	if err := registry.Add(resources...); err != nil {
		return err
	}

	serializedResources, err := registry.SerializedObjects()
	if err != nil {
		return err
	}

	if err := managedresources.CreateForSeedWithLabels(
		ctx,
		k.client,
		k.namespace,
		k.managedResourceName(),
		false,
		map[string]string{v1beta1constants.LabelCareConditionType: v1beta1constants.ObservabilityComponentsHealthy},
		serializedResources,
	); err != nil {
		return err
	}

	registryTarget := managedresources.NewRegistry(operatorclient.VirtualScheme, operatorclient.VirtualCodec, operatorclient.VirtualSerializer)
	resourcesTarget, err := registryTarget.AddAllAndSerialize(k.getResourcesForVirtualTarget(virtualAccessSecret)...)
	if err != nil {
		return err
	}

	return managedresources.CreateForShootWithLabels(
		ctx,
		k.client,
		k.namespace,
		k.managedResourceName()+"-target",
		managedresources.LabelValueGardener,
		false,
		map[string]string{v1beta1constants.LabelCareConditionType: v1beta1constants.ObservabilityComponentsHealthy},
		resourcesTarget,
	)
}

func (k *kubeStateMetrics) Destroy(ctx context.Context) error {
	if err := managedresources.DeleteForSeed(ctx, k.client, k.namespace, k.managedResourceName()); err != nil {
		return err
	}

	if k.values.ClusterType == component.ClusterTypeShoot {
		if err := managedresources.DeleteForShoot(ctx, k.client, k.namespace, k.managedResourceName()+"-target"); err != nil {
			return err
		}

		return client.IgnoreNotFound(k.client.Delete(ctx, k.newShootAccessSecret().Secret))
	}

	return nil
}

// TimeoutWaitForManagedResource is the timeout used while waiting for the ManagedResources to become healthy
// or deleted.
var TimeoutWaitForManagedResource = 2 * time.Minute

func (k *kubeStateMetrics) Wait(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilHealthy(timeoutCtx, k.client, k.namespace, k.managedResourceName())
}

func (k *kubeStateMetrics) WaitCleanup(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilDeleted(timeoutCtx, k.client, k.namespace, k.managedResourceName())
}

func (k *kubeStateMetrics) managedResourceName() string {
	if k.values.ClusterType == component.ClusterTypeSeed {
		return managedResourceName + k.values.NameSuffix
	}
	return managedResourceNameShoot + k.values.NameSuffix
}
