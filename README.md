# cert-manager-webhook-volcengine

This is a cert-manager webhook solver for [Volcengine-trafficroute](https://www.volcengine.com/product/trafficroute).

## Prerequisites

* [cert-manager](https://github.com/cert-manager/cert-manager) >= 1.13.0

## Installation

### Use Helm

First, generate `AccessKey` and `SecretKey` in [Cloud API](https://console.volcengine.com/iam/keymanage/)

You can install chart from git repo:

```bash
$ helm install --name cert-manager-webhook-volcengine ./deploy/cert-manager-webhook-volcengine \
    --namespace <NAMESPACE-WHICH-CERT-MANAGER-INSTALLED> \
    --set groupName=<GROUP_NAME> \
    --set clusterIssuer.enabled=true,clusterIssuer.email=<EMAIL_ADDRESS>
```

Create the secret holding volcegine credential, accessKey need input AccessKeyId, secretKey need input SecretAccessKey:
```
kubectl create secret generic volcengine-secrets --from-literal="accessKey=youraccesskey" --from-literal="secretKey=yoursecretkey"
```

### Use Kubectl

Use `kubectl apply` to install:

```bash
kubectl apply -f https://raw.githubusercontent.com/imroc/cert-manager-webhook-volcengine/master/bundle.yaml
```

## Usage

### Cridentials

Firstly, create a secret that contains Volcengine account's `AccessKey` and `SecretKey`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: volcengine-secret
  namespace: cert-manager
type: Opaque
stringData:
  accessKey: xxx
  secretKey: xxx
```

> Base64 is not needed in `stringData`.

### Create Issuer

Before you can issue a certificate, you need to create a `Issuer` or `ClusterIssuer`.

> If you use helm and only need a global `ClusterIssuer`, you can add `--set clusterIssuer.enabled=true --set clusterIssuer.accessKey=xxx --set clusterIssuer.secretKey=xxx` to create the `ClusterIssuer`.

Create a `ClusterIssuer` referring the secret:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: volcengine
spec:
  acme:
    email: roc@imroc.cc
    privateKeySecretRef:
      name: volcengine-letsencrypt
    server: https://acme-v02.api.letsencrypt.org/directory
    solvers:
      - dns01:
          webhook:
            config:
              accessKeyRef:
                key: accessKey
                name: volcengine-secret
              secretKeyRef:
                key: secretKey
                name: volcengine-secret
              ttl: 600
            groupName: acme.volcengine.com
            solverName: volcengine
```

1. `accessKey` and `secretKey` is the AccessKey and SecretKey of your Volcengine account.
2. `groupName` is the the groupName that specified in your cert-manager-webhook-volcengine installation, defaults to `acme.volcengine.com`.
3. `solverName` must be `volcengine`.
4. `ttl` is the optional ttl of dns TXT record that created by webhook.
5. `regionId` is the optional regionId parameter of the volcengine.
6. `email` is the optional email address. When the domain is about to expire, a notification will be sent to this email address.

### Create Certificate

You can issue the certificate by creating `Certificate` that referring the volcengine `ClusterIssuer` or `Issuer`:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-crt
spec:
  secretName: example-crt
  issuerRef:
    name: volcengine
    kind: ClusterIssuer
    group: cert-manager.io
  dnsNames:
    - "example.com"
    - "*.example.com"
```
