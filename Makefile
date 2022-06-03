all:
	@go build -o rawhttpget && echo Successful build

clean:
	@rm ./rawhttpget