{{- define "cryptoscan.labels" -}}
app.kubernetes.io/part-of: cryptoscan
app.kubernetes.io/managed-by: {{ .Release.Service | default "helm" }}
{{- end -}}
