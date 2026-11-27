{{- define "nydus-snapshotter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nydus-snapshotter.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "nydus-snapshotter.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "nydus-snapshotter.labels" -}}
app.kubernetes.io/name: {{ include "nydus-snapshotter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: nydus
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "nydus-snapshotter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nydus-snapshotter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "nydus-snapshotter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "nydus-snapshotter.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "nydus-snapshotter.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- /* Strategic merge patch that turns the hostSystemd DaemonSet into its removal mode. */}}
{{- define "nydus-snapshotter.uninstallPatch" -}}
{{- $env := list (dict "name" "HOST_SYSTEMD_ACTION" "value" "uninstall") -}}
{{- $spec := dict "containers" (list (dict "name" "host-systemd" "env" $env)) -}}
{{- if .Values.containerd.install.enable -}}
{{- $_ := set $spec "initContainers" (list (dict "name" "containerd-config-installer" "env" $env)) -}}
{{- end -}}
{{- dict "spec" (dict "updateStrategy" (dict "type" "RollingUpdate" "rollingUpdate" (dict "maxUnavailable" "100%")) "template" (dict "spec" $spec)) | toJson -}}
{{- end -}}
