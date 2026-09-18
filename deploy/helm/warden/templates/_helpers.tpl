{{- define "warden.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "warden.fullname" -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "warden.labels" -}}
app.kubernetes.io/name: {{ include "warden.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "warden.selector" -}}
app.kubernetes.io/name: {{ include "warden.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "warden.env" -}}
envFrom:
  - configMapRef: { name: {{ include "warden.fullname" . }} }
  {{- if .Values.existingSecret }}
  - secretRef: { name: {{ .Values.existingSecret }} }
  {{- end }}
{{- end -}}
{{- define "warden.volume" -}}
- name: data
  {{- if .Values.persistence.enabled }}
  persistentVolumeClaim: { claimName: {{ include "warden.fullname" . }} }
  {{- else }}
  emptyDir: {}
  {{- end }}
{{- end -}}
