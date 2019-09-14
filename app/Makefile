maven_img := maven:3.6.1-jdk-11-slim

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
curr_dir := $(patsubst %/,%,$(dir $(mkfile_path)))
curr_dir_sha := $(shell echo -n "$(curr_dir)" | shasum | cut -c1-7)

mvn_build_container_name := mvn-build-${curr_dir_sha}

build: _create_mvn_container _mvn_package
	$(info *** ONOS app .oar package created succesfully)
	@ls -1 target/*.oar

# Reuse the same container to persist mvn repo cache.
_create_mvn_container:
	@if ! docker container ls -a --format '{{.Names}}' | grep -q ${mvn_build_container_name} ; then \
		docker create -v ${curr_dir}:/mvn-src -w /mvn-src --name ${mvn_build_container_name} ${maven_img} mvn clean package; \
	fi

_mvn_package: _copy_p4c_out
	$(info *** Building ONOS app...)
	@mkdir -p target
	@docker start -a -i ${mvn_build_container_name}

_copy_p4c_out:
	rm -rf src/main/resources/p4c-out
	mkdir -p src/main/resources/p4c-out	
	cp -r ../p4src/build/* src/main/resources/p4c-out

clean:
	@-docker rm ${mvn_build_container_name} > /dev/null
	@-rm -rf target