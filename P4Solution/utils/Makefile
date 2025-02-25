BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

TOPO = topology.json
P4C = p4c-bm2-ss
RUN_SCRIPT = ../../utils/run_mn.py

#source := $(wildcard *.p4)
source := ddos.p4
json_out := $(source:.p4=.json)
p4info_out := $(source:.p4=.p4info.txt)

compiled_json := $(BUILD_DIR)/$(json_out)
compiled_p4info := $(BUILD_DIR)/$(p4info_out)

# Define NO_P4 to start BMv2 without a program
ifndef NO_P4
run_args += -j $(compiled_json)
endif

# Set BMV2_SWITCH_EXE to override the BMv2 target
ifdef BMV2_SWITCH_EXE
run_args += -b $(BMV2_SWITCH_EXE)
endif

all: run

run: build
	sudo PYTHONPATH=/home/p4/.local/lib/python3.8/site-packages:/home/p4/tutorials/utils:/home/p4/tutorials/utils/p4runtime_lib /usr/local/bin/python3.8 $(RUN_SCRIPT) -t $(TOPO) $(run_args)


stop:
	sudo mn -c

build: dirs $(compiled_json) $(compiled_p4info)

$(BUILD_DIR)/%.json $(BUILD_DIR)/%.p4info.txt: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $(BUILD_DIR)/$*.json --p4runtime-files $(BUILD_DIR)/$*.p4info.txt $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
