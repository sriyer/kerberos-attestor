export GO111MODULE=on

binary_dirs := agent server
out_dir := bin

build: $(binary_dirs)

$(binary_dirs): noop
	cd $@ && go build -o ../$(out_dir)/$@ -i

vendor:
	go mod vendor

test:
	go test -race ./...

noop:

.PHONY: all build vendor utils test clean
