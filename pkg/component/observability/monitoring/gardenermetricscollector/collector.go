// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardenermetricscollector

import (
	"fmt"
	"strconv"

	otelv1beta1 "github.com/open-telemetry/opentelemetry-operator/apis/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	kubeapiserverconstants "github.com/gardener/gardener/pkg/component/kubernetes/apiserver/constants"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
)

const (
	// metricsPortName is the name of the Service port that the OpenTelemetry Operator creates for the Prometheus
	// exporter. The ServiceMonitor references it by this name.
	metricsPortName = "metrics"

	// kubeconfigVolumeName is the name of the volume holding the projected generic kubeconfig used by the Gardener
	// metrics receiver to talk to the virtual garden API server.
	kubeconfigVolumeName = "kubeconfig"
)

func (g *gardenerMetricsCollector) openTelemetryCollector(genericTokenKubeconfigSecretName, virtualGardenAccessSecretName string) *otelv1beta1.OpenTelemetryCollector {
	obj := &otelv1beta1.OpenTelemetryCollector{
		ObjectMeta: metav1.ObjectMeta{
			Name:      openTelemetryCollectorName,
			Namespace: g.namespace,
			Labels:    GetLabels(),
		},
		Spec: otelv1beta1.OpenTelemetryCollectorSpec{
			Mode:            "deployment",
			UpgradeStrategy: "none",
			Observability: otelv1beta1.ObservabilitySpec{
				Metrics: otelv1beta1.MetricsConfigSpec{
					DisablePrometheusAnnotations: true,
				},
			},
			OpenTelemetryCommonFields: otelv1beta1.OpenTelemetryCommonFields{
				Image:             g.values.Image,
				Replicas:          new(int32(1)),
				PriorityClassName: v1beta1constants.PriorityClassNameGardenSystem100,
				ServiceAccount:    openTelemetryCollectorName,
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("10m"),
						corev1.ResourceMemory: resource.MustParse("50Mi"),
					},
				},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: new(false),
					ReadOnlyRootFilesystem:   new(true),
				},
				Volumes: []corev1.Volume{
					gardenerutils.GenerateGenericKubeconfigVolume(genericTokenKubeconfigSecretName, virtualGardenAccessSecretName, kubeconfigVolumeName),
				},
				VolumeMounts: []corev1.VolumeMount{
					gardenerutils.GenerateGenericKubeconfigVolumeMount(kubeconfigVolumeName, gardenerutils.VolumeMountPathGenericKubeconfig),
				},
				// The Prometheus exporter port must be declared explicitly. The OpenTelemetry Operator does not derive
				// Service ports from the exporter configuration, so without this entry the garden Prometheus could not
				// scrape the exposed metrics.
				Ports: []otelv1beta1.PortsSpec{{
					ServicePort: corev1.ServicePort{
						Name:     metricsPortName,
						Port:     metricsPort,
						Protocol: corev1.ProtocolTCP,
					},
				}},
			},
			Config: otelv1beta1.Config{
				Receivers: otelv1beta1.AnyConfig{
					Object: map[string]any{
						"gardener": map[string]any{
							"kubeconfig": gardenerutils.PathGenericKubeconfig},
					},
				},
				Exporters: otelv1beta1.AnyConfig{
					Object: map[string]any{
						"prometheus": map[string]any{
							"endpoint": "[::]:" + strconv.Itoa(metricsPort),
						},
					},
				},
				Service: otelv1beta1.Service{
					// Telemetry configures the collector's own self-observability metrics (otelcol_*). The
					// OpenTelemetry Operator serves them on a separate "monitoring" service; internalMetricsServiceMonitor
					// scrapes that service.
					Telemetry: &otelv1beta1.AnyConfig{
						Object: map[string]any{
							"metrics": map[string]any{
								"level": "basic",
								"readers": []any{
									map[string]any{
										"pull": map[string]any{
											"exporter": map[string]any{
												"prometheus": map[string]any{
													"host": "[::]",
													"port": internalMetricsPort,
												},
											},
										},
									},
								},
							},
						},
					},
					Pipelines: map[string]*otelv1beta1.Pipeline{
						"metrics": {
							Receivers: []string{"gardener"},
							Exporters: []string{"prometheus"},
						},
					},
				},
			},
		},
	}

	// The Gardener metrics receiver talks to the virtual garden kube-apiserver, so the collector pods need the
	// corresponding network policy label.
	metav1.SetMetaDataLabel(&obj.ObjectMeta, gardenerutils.NetworkPolicyLabel(operatorv1alpha1.DeploymentNameVirtualGardenKubeAPIServer, kubeapiserverconstants.Port), v1beta1constants.LabelNetworkPolicyAllowed)
	metav1.SetMetaDataLabel(&obj.ObjectMeta, v1beta1constants.LabelNetworkPolicyToDNS, v1beta1constants.LabelNetworkPolicyAllowed)

	// Annotations set on the OpenTelemetryCollector resource are propagated by the OpenTelemetry Operator to the
	// resources it creates - in particular to the Service that the garden Prometheus scrapes. This is currently the
	// only way to make the operator-created Service selectable as a garden scrape target.
	metav1.SetMetaDataAnnotation(&obj.ObjectMeta, resourcesv1alpha1.NetworkPolicyFromPolicyAnnotationPrefix+v1beta1constants.LabelNetworkPolicyGardenScrapeTargets+resourcesv1alpha1.NetworkPolicyFromPolicyAnnotationSuffix, fmt.Sprintf(`[{"protocol":"TCP","port":%d},{"protocol":"TCP","port":%d}]`, metricsPort, internalMetricsPort))

	return obj
}
