
make recreate:
	docker compose down
	# docker rm plugin-os-ubuntu-gotest-1
	docker compose up -d 

make test:
	docker exec plugin-os-ubuntu-gotest-1 bash -c "go test -v ./..."