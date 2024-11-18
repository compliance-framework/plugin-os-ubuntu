make down:
	docker compose down

make purge:
	make down 
	docker image rm plugin-os-ubuntu-gotest
make up:
	docker compose up -d --force-recreate

make test:
	docker exec plugin-os-ubuntu-gotest-1 bash -c "go test -v ./..."