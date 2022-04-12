TARGET := rawhttpget

PWD := $(shell pwd)

all:
	@go build -o $(PWD)/bin/rawhttpget && echo Successful build

clean:
	@rm -rf bin/*