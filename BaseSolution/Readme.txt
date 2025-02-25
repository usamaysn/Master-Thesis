ddos_detect.py: This is the script that is called my java application to make predictions using rf_model.sav

ddos_blocklist.csv: This is the file where the DDoS sources are saved

traffic.pcap: This is file captured using tcpdump during the simulations.

traffic_dataset.csv: This is the data extracted from traffic.pcap file using CICflowmeter and on this predictions are made using rf_model.sav and then saved in ddos_blocklist.csv.

Onos_App: This is the folder that contains the java application.