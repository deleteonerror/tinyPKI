include build/docker.Makefile

export TINY_LOG=Debug

build: build-root build-sub build-req

build-root:
	go build -o bin/tpkiroot -v cmd/tpkiroot/main.go 
build-sub:
	go build -o bin/tpkisub -v cmd/tpkisub/main.go 
build-req:
	go build -o bin/tpkireq -v cmd/tpkireq/main.go 

config-sub:
	mkdir -p $(CURDIR)/bin/sub_data/work
	cp configs/tinypki.sub.example.json $(CURDIR)/bin/sub_data/work/config.json

config-root:
	mkdir -p $(CURDIR)/bin/root_data/work
	cp configs/tinypki.root.example.json $(CURDIR)/bin/root_data/work/config.json

run-root: build-root config-root
	export TINY_ROOT_PATH=$(CURDIR)/bin/root_data; \
	./bin/tpkiroot

rerun-root:
	export TINY_ROOT_PATH=$(CURDIR)/bin/root_data; \
	./bin/tpkiroot

run-sub: build-sub config-sub
	export TINY_ROOT_PATH=$(CURDIR)/bin/sub_data; \
	./bin/tpkisub

rerun-sub:
	export TINY_ROOT_PATH=$(CURDIR)/bin/sub_data; \
	 ./bin/tpkisub

run-req: build-req
	./bin/tpkireq

clean:
	go clean
	rm -f bin/tpkiroot
	rm -f bin/tpkisub 
	rm -f bin/tpkireq
	rm -rf bin/sub_data
	rm -rf bin/root_data

deps:
	go mod download

test: 
	go test -v ./...
