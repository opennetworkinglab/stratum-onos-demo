mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(patsubst %/,%,$(dir $(mkfile_path)))
build_dir := ${current_dir}/build

docker_run := docker run --rm -v ${current_dir}:${current_dir} -w ${current_dir}

p4c_bmv2_img := opennetworking/p4c:stable
p4c_bm2_ss := ${docker_run} ${p4c_bmv2_img} p4c-bm2-ss --arch v1model


bmv2: bmv2-pp
	# Generate bmv2.json and p4info.txt
	${p4c_bm2_ss} -o ${build_dir}/bmv2/bmv2.json \
		--p4runtime-files ${build_dir}/bmv2/p4info.txt max.p4

bmv2-pp:
	mkdir -p ${build_dir}/bmv2
	# Generate preprocessed source (for debugging)
	${p4c_bm2_ss} --pp ${build_dir}/bmv2/pp.p4 max.p4

clean:
	-rm -rf ${build_dir}
