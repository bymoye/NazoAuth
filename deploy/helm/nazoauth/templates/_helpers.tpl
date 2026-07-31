{{- define "nazoauth.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nazoauth.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "nazoauth.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nazoauth.labels" -}}
app.kubernetes.io/name: {{ include "nazoauth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}
