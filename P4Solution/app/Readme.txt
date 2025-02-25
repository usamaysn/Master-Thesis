controlplane.txt: This is control plane logs file.

controlplane.py: This is the python control plane application.

ddos.p4: This is the p4 application.

ddos_detect.py: This is the script that is called my control plane application to make predictions using rf_model.sav

p4cap.csv: This is the dataset extracted via CICflowmeter from ddos simulations and predictions are made on this dataset.

ddos_sources.csv: This is file where the DDoS detection predictions are stored such as IP with the most count as in source of DDoS.

topology.json: This is the topology file that Is called by Makefile when the make command is initiated in the terminal. This command runs mininet, starts bmv2, and also makes topology.