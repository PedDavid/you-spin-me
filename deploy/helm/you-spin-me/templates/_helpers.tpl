{{- define "ysm.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ysm.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ysm.labels" -}}
app.kubernetes.io/name: {{ include "ysm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "ysm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ysm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ysm.apiKeysNamespace" -}}
{{- default .Release.Namespace .Values.apiKeysNamespace -}}
{{- end -}}

{{- define "ysm.cookieSecretName" -}}
{{- default (printf "%s-cookie-key" (include "ysm.fullname" .)) .Values.cookieKey.existingSecret -}}
{{- end -}}
