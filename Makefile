.PHONY: all bpf build clean run test deploy deploy-crd deploy-rbac deploy-webhook webhook-cert

all: bpf build

bpf:
	$(MAKE) -C bpf

build: bpf
	go build -o bin/patrold ./cmd/patrold

run: build
	sudo ./bin/patrold

# 기존 kubectl 모드로 실행
run-kubectl: build
	sudo -E ./bin/patrold --scope containers --k8s-intents --k8s-mode kubectl

# CRD 모드로 실행 (informer + webhook)
run-crd: build
	sudo -E ./bin/patrold \
		--scope containers \
		--k8s-intents \
		--k8s-mode crd \
		--k8s-sync-interval 5s \
		--webhook-enable \
		--webhook-port 8443 \
		--webhook-cert-dir ./certs

test:
	go test ./internal/fusion ./internal/intent ./internal/policy

clean:
	$(MAKE) -C bpf clean
	rm -rf bin/ gen/*.o

# ─── Kubernetes 배포 ───

deploy: deploy-crd deploy-rbac deploy-webhook
	kubectl apply -f deploy/daemonset.yaml

deploy-crd:
	kubectl apply -f deploy/crd/workloadintent-crd.yaml

deploy-rbac:
	kubectl apply -f deploy/rbac.yaml

deploy-webhook:
	kubectl apply -f deploy/webhook.yaml

deploy-samples:
	kubectl apply -f deploy/crd/samples/

webhook-cert:
	bash scripts/gen-webhook-cert.sh

# CRD 제거
undeploy:
	kubectl delete -f deploy/daemonset.yaml --ignore-not-found
	kubectl delete -f deploy/webhook.yaml --ignore-not-found
	kubectl delete -f deploy/rbac.yaml --ignore-not-found
	kubectl delete -f deploy/crd/workloadintent-crd.yaml --ignore-not-found