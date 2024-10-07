// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kubestatemetrics

import (
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func (k *kubeStateMetrics) serviceAccount() *corev1.ServiceAccount {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "kube-state-metrics" + k.values.NameSuffix, Namespace: k.namespace}}
	serviceAccount.Labels = k.getLabels()
	serviceAccount.AutomountServiceAccountToken = ptr.To(false)
	return serviceAccount
}

type ClusterRoleOption func(*rbacv1.ClusterRole)

func WithDefaultRules() ClusterRoleOption {
	return func(role *rbacv1.ClusterRole) {
		rules := []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{
					"nodes",
					"pods",
					"services",
					"resourcequotas",
					"replicationcontrollers",
					"limitranges",
					"persistentvolumeclaims",
					"namespaces",
				},
				Verbs: []string{"list", "watch"},
			},
			{
				APIGroups: []string{"apps", "extensions"},
				Resources: []string{"daemonsets", "deployments", "replicasets", "statefulsets"},
				Verbs:     []string{"list", "watch"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{"cronjobs", "jobs"},
				Verbs:     []string{"list", "watch"},
			},
			{
				APIGroups: []string{"apiextensions.k8s.io"},
				Resources: []string{"customresourcedefinitions"},
				Verbs:     []string{"list", "watch"},
			},
			{
				APIGroups: []string{"autoscaling.k8s.io"},
				Resources: []string{"verticalpodautoscalers"},
				Verbs:     []string{"list", "watch"},
			},
		}
		role.Rules = append(role.Rules, rules...)
	}
}

func WithGardenerOperatorRules() ClusterRoleOption {
	return func(role *rbacv1.ClusterRole) {
		rules := []rbacv1.PolicyRule{
			{
				APIGroups: []string{"operator.gardener.cloud"},
				Resources: []string{"gardens"},
				Verbs:     []string{"list", "watch"},
			},
		}
		role.Rules = append(role.Rules, rules...)
	}
}

func WithHorizontalPodAutoscalerRules() ClusterRoleOption {
	return func(role *rbacv1.ClusterRole) {
		rules := []rbacv1.PolicyRule{
			{
				APIGroups: []string{"autoscaling"},
				Resources: []string{"horizontalpodautoscalers"},
				Verbs:     []string{"list", "watch"},
			},
		}
		role.Rules = append(role.Rules, rules...)
	}
}

func (k *kubeStateMetrics) clusterRole(options ...ClusterRoleOption) *rbacv1.ClusterRole {
	clusterRole := rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "gardener.cloud:monitoring:" + k.nameSuffix()}}
	clusterRole.Labels = k.getLabels()
	clusterRole.Rules = []rbacv1.PolicyRule{}

	for _, opt := range options {
		opt(&clusterRole)
	}

	return &clusterRole
}

func (k *kubeStateMetrics) clusterRoleBinding(clusterRole *rbacv1.ClusterRole, serviceAccount *corev1.ServiceAccount) *rbacv1.ClusterRoleBinding {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "gardener.cloud:monitoring:" + k.nameSuffix()}}
	clusterRoleBinding.Labels = k.getLabels()
	clusterRoleBinding.Annotations = map[string]string{resourcesv1alpha1.DeleteOnInvalidUpdate: "true"}
	clusterRoleBinding.RoleRef = rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "ClusterRole",
		Name:     clusterRole.Name,
	}
	clusterRoleBinding.Subjects = []rbacv1.Subject{{
		Kind:      rbacv1.ServiceAccountKind,
		Name:      serviceAccount.Name,
		Namespace: serviceAccount.Namespace,
	}}

	return clusterRoleBinding
}
