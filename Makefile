test: clean
	@echo "Testing policies..."
	@opa eval -i vulnerabilities.json -d ./policies/vulnerability_check.rego "data.security.vulnerabilities.deny"
	@opa eval -i vulnerabilities.json -d ./policies/vulnerability_check.rego "data.security.vulnerabilities.warn"

build: clean
	@echo "Bundling policies..."
	@mkdir -p dist/
	@opa build -b policies -o dist/bundle.tar.gz

clean:
	@echo "Cleaning up..."
	@rm -f dist/bundle.tar.gz