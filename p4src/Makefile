mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(patsubst %/,%,$(dir $(mkfile_path)))
sha1 := $(shell echo -n "$(current_dir)" | shasum | cut -c1-7)

build_dir := ${current_dir}/build

docker_run := docker run --rm -v ${current_dir}:${current_dir}

p4c_bmv2_img := opennetworking/p4c:stable
p4c_bmv2 := ${docker_run} -w ${current_dir} ${p4c_bmv2_img} p4c-bm2-ss --arch v1model
bf_sde_img := opennetworking/bf-sde:8.9.1
p4c_tofino := ${docker_run} -w ${current_dir} ${bf_sde_img} bf-p4c --arch v1model
p4i_tofino := ${docker_run} -w ${build_dir}/tofino -p3000:3000 -d --name p4i-${sha1} ${bf_sde_img} p4i

.PHONY: build

build: bmv2 tofino

bmv2: bmv2-pp
	### Generate bmv2.json and p4info.txt
	###
	mkdir -p ${build_dir}/bmv2
	${p4c_bmv2} -o ${build_dir}/bmv2/bmv2.json \
		--p4runtime-files ${build_dir}/bmv2/p4info.txt max.p4

bmv2-pp:
	### Generate preprocessed source (for debugging)
	###
	mkdir -p ${build_dir}/bmv2
	${p4c_bmv2} --pp ${build_dir}/bmv2/pp.p4 max.p4

tofino:
	### Generate tofino.bin
	###
	mkdir -p ${build_dir}/tofino
	${p4c_tofino} -g -o ${build_dir}/tofino \
		--p4runtime-files ${build_dir}/bmv2/p4info.txt max.p4

p4i-start:
	### Starting p4i container...
	### Use `make p4i-stop` to kill the p4i container
	###
	${p4i_tofino}
	@make p4i-log

p4i-log:
	### Showing p4i log...
	###
	-docker logs -f p4i-${sha1}

p4i-stop:
	### Stopping p4i container...
	###
	docker stop -t0 p4i-${sha1}

clean:
	-rm -rf ${build_dir}
