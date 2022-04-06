export GO111MODULE=on

binary_dirs := agent server
out_dir := bin

build: $(binary_dirs)

$(binary_dirs): noop
	cd $@ && go mod vendor && go build -mod=vendor -o ../$(out_dir)/$@

test:
	go test -race ./...

noop:

.PHONY: all build vendor utils test clean
