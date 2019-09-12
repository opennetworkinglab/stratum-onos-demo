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
p4c_fpm_img := opennetworking/p4c-fpm:latest
p4c_fpm := ${docker_run} -w ${current_dir} ${p4c_fpm_img} p4c

cpu_port_bmv2 := 253
cpu_port_fpm := 253
cpu_port_mavericks := 320
cpu_port_montara := 192

.PHONY: build

build: bmv2 tofino fpm

docker-pull:
	docker pull ${p4c_fpm_img}
	docker pull ${bf_sde_img}
	docker pull ${p4c_bmv2_img}

bmv2: bmv2-pp
	### Generate bmv2.json and p4info.txt
	###
	mkdir -p ${build_dir}/bmv2
	${p4c_bmv2} -o ${build_dir}/bmv2/bmv2.json \
		--Wdisable=unsupported --p4runtime-files ${build_dir}/bmv2/p4info.txt \
		main.p4
	echo ${cpu_port_bmv2} > ${build_dir}/bmv2/cpu_port.txt

bmv2-pp:
	### Generate preprocessed source (for debugging)
	###
	mkdir -p ${build_dir}/bmv2
	${p4c_bmv2} --pp ${build_dir}/bmv2/pp.p4 --Wdisable=unsupported main.p4

tofino-base:
	### Generate tofino.bin and p4info
	###
	mkdir -p ${build_dir}/tofino-$(NAME)
	${p4c_tofino} -g -o ${build_dir}/tofino-$(NAME) -DCPU_PORT=$(CPU_PORT) \
		--Wdisable=unknown --p4runtime-files ${build_dir}/tofino-$(NAME)/p4info.txt \
		main.p4
	echo $(CPU_PORT) > ${build_dir}/tofino-$(NAME)/cpu_port.txt

tofino-mavericks:
	$(MAKE) tofino-base NAME=mavericks CPU_PORT=${cpu_port_mavericks}

tofino-montara:
	$(MAKE) tofino-base NAME=montara CPU_PORT=${cpu_port_montara}

tofino: tofino-montara tofino-mavericks

fpm:
	### Generate pipeline_config.bin/.txt and p4info.txt
	###
	mkdir -p ${build_dir}/fpm
	${p4c_fpm} --p4c_fe_options=" \
			-I /usr/share/p4c/p4include \
			--std=p4-16 \
			--target=BCM \
			--Wdisable=legacy \
			--Wwarn=all \
			main.p4" \
		--p4_info_file=${build_dir}/fpm/p4info.txt \
		--p4_pipeline_config_text_file=${build_dir}/fpm/pipeline_config.txt \
		--p4_pipeline_config_binary_file=${build_dir}/fpm/pipeline_config.bin \
		--p4c_annotation_map_files=table_map.pb.txt,field_map.pb.txt \
		--target_parser_map_file=standard_parser_map.pb.txt \
		--slice_map_file=sliced_field_map.pb.txt
	echo ${cpu_port_fpm} > ${build_dir}/fpm/cpu_port.txt

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
