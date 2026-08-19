# Runs inside the vulnreach-observer-build container with the source bind-mounted.
# vmlinux needs /sys/kernel/btf/vmlinux -> run the build container --privileged.

.PHONY: all vmlinux tidy generate build clean

all: vmlinux tidy generate build

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

tidy:
	go mod tidy

generate:
	go generate ./...

build:
	CGO_ENABLED=0 go build -o bin/vulnreach-observer .

clean:
	rm -f vmlinux.h observer_bpf*.go observer_bpf*.o
	rm -rf bin
