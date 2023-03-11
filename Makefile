all:
	@go build -o rawhttpget && echo Successful build

test:
	@go test -v ./...

clean:
	@rm ./rawhttpget