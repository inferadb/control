{{/*
Expand the name of the chart.
*/}}
{{- define "inferadb-control.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "inferadb-control.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "inferadb-control.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "inferadb-control.labels" -}}
helm.sh/chart: {{ include "inferadb-control.chart" . }}
{{ include "inferadb-control.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: inferadb
{{- end }}

{{/*
Selector labels
*/}}
{{- define "inferadb-control.selectorLabels" -}}
app.kubernetes.io/name: {{ include "inferadb-control.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: control-plane
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "inferadb-control.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "inferadb-control.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the config secret
*/}}
{{- define "inferadb-control.secretName" -}}
{{- printf "%s-secrets" (include "inferadb-control.fullname" .) }}
{{- end }}

{{/*
Create the name of the configmap
*/}}
{{- define "inferadb-control.configMapName" -}}
{{- printf "%s-config" (include "inferadb-control.fullname" .) }}
{{- end }}

{{/*
Determine if Tailscale sidecar should be enabled
*/}}
{{- define "inferadb-control.tailscaleEnabled" -}}
{{- if and (eq .Values.discovery.mode "tailscale") .Values.discovery.tailscale.enabled }}
{{- true }}
{{- else }}
{{- false }}
{{- end }}
{{- end }}
