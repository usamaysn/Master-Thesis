#!/usr/bin/env python3.8

import sys
import os
import socket
import struct
import logging
import grpc
import time
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc

sys.path.append(os.path.join(os.path.dirname(__file__), '../../utils'))

from p4runtime_lib.switch import ShutdownAllSwitchConnections, SwitchConnection
from p4runtime_lib.helper import P4InfoHelper

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(message)s',
    handlers=[
        logging.FileHandler("controlplane.log"),
        logging.StreamHandler()
    ]
)

P4INFO_FILE_PATH = "/build/ddos.p4info.txt"
P4_BINARY_PATH = "/build/ddos.json"
MODEL_PATH = "rf_model.sav"
file_path = "p4cap.csv"

model = joblib.load(MODEL_PATH)

def load_and_prepare_data(file_path):
    ntraffic_data = pd.read_csv(file_path)

    # Define the features
    features = ['Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min']

    # Strip leading and trailing spaces from column names
    ntraffic_data.columns = ntraffic_data.columns.str.strip()

    # Select the specified top features from the new dataset
    X_new = ntraffic_data[features]

    # Convert the data to the same format as used during training
    X_new = X_new.values

    # Check for infinite values and replace them with NaN
    X_new = pd.DataFrame(X_new)
    X_new.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Fill NaN values with the mean of the respective columns
    X_new.fillna(X_new.mean(), inplace=True)

    # Clip the values to a reasonable range to avoid extremely large values
    X_new = X_new.clip(lower=np.finfo(np.float32).min, upper=np.finfo(np.float32).max)

    # Convert back to NumPy array if necessary
    return X_new.values, ntraffic_data


def connect_to_switch(p4info_file_path, p4_binary_path, p4runtime_address, device_id):
    p4info_helper = P4InfoHelper(p4info_file_path)
    switch_connection = SwitchConnection(
        name='switch',
        address=p4runtime_address,
        device_id=device_id,
        proto_dump_file='logs/p4runtime_requests.txt'
    )
    switch_connection.MasterArbitrationUpdate()
    switch_connection.SetForwardingPipelineConfig(
        p4info=p4info_helper.p4info,
        bmv2_json_file_path=p4_binary_path
    )
    logging.info("Connected to switch and set forwarding pipeline config.")
    logging.debug("P4 Info: %s", p4info_helper.p4info)
    return switch_connection, p4info_helper

def add_default_forwarding_rules(switch_connection, p4info_helper):
    try:
        table_entry_1 = p4info_helper.buildTableEntry(
            table_name="MyIngress.forward",
            match_fields={
                "hdr.ethernet.dstAddr": "00:00:00:00:01:01"
            },
            action_name="MyIngress.set_egress_port",
            action_params={
                "port": 1
            }
        )
        switch_connection.WriteTableEntry(table_entry_1)
        logging.info("Added default forwarding rule for 00:00:00:00:01:01 -> port 1")

        table_entry_2 = p4info_helper.buildTableEntry(
            table_name="MyIngress.forward",
            match_fields={
                "hdr.ethernet.dstAddr": "00:00:00:00:01:02"
            },
            action_name="MyIngress.set_egress_port",
            action_params={
                "port": 2
            }
        )
        switch_connection.WriteTableEntry(table_entry_2)
        logging.info("Added default forwarding rule for 00:00:00:00:01:02 -> port 2")

        table_entry_3 = p4info_helper.buildTableEntry(
            table_name="MyIngress.forward",
            match_fields={
                "hdr.ethernet.dstAddr": "00:00:00:00:01:03"
            },
            action_name="MyIngress.set_egress_port",
            action_params={
                "port": 3
            }
        )
        switch_connection.WriteTableEntry(table_entry_3)
        logging.info("Added default forwarding rule for 00:00:00:00:01:03 -> port 3")

    except grpc.RpcError as e:
        logging.error(f"gRPC Error: {e.details()}")
        logging.error(f"gRPC Debug Info: {e.debug_error_string()}")

def add_arp_entry(switch_connection, p4info_helper, ip_addr, mac_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.arp_cache",
        match_fields={
            "hdr.arp.tpa": ip_addr
        },
        action_name="MyIngress.send_arp_response",
        action_params={
            "src_mac": mac_addr,
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": ip_addr,
            "dst_ip": ip_addr
        }
    )
    switch_connection.WriteTableEntry(table_entry)
    logging.info("Added ARP entry for {} -> {}".format(ip_addr, mac_addr))


def remove_arp_entry(switch_connection, p4info_helper, ip_addr):
    try:
        # Create a table entry for deletion
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.arp_cache",
            match_fields={
                "hdr.arp.tpa": ip_addr
            },
            action_name="NoAction",  
            action_params={}
        )

        request = p4runtime_pb2.WriteRequest()
        request.device_id = switch_connection.device_id
        request.election_id.high = 0
        request.election_id.low = 1

        update = request.updates.add()
        update.type = p4runtime_pb2.Update.DELETE
        update.entity.table_entry.CopyFrom(table_entry)

        switch_connection.client_stub.Write(request)
        logging.info(f"Removed ARP entry for IP: {ip_addr}")
    except grpc.RpcError as e:
        logging.error(f"Failed to remove ARP entry for IP: {ip_addr}")
        logging.error(f"gRPC Error: {e.details()}")
        logging.error(f"gRPC Debug Info: {e.debug_error_string()}")


def analyze_traffic(switch_connection, p4info_helper, file_path):
    X_new, ntraffic_data = load_and_prepare_data(file_path)

    # Make predictions on the new dataset
    predictions = model.predict(X_new)
    probabilities = model.predict_proba(X_new)

    # Output the predictions
    ntraffic_data['Predictions'] = predictions
    print(ntraffic_data[['Predictions']])

    # Class distribution in the new data
    print("Class distribution in the new data:")
    print(ntraffic_data['Predictions'].value_counts())

    # Filter out the DDoS entries
    ddos_entries = ntraffic_data[ntraffic_data['Predictions'] == 1] 

    # Extract the source IPs of the DDoS traffic
    ddos_sources = ddos_entries['Source IP']

    # Count the frequency of each source IP
    source_counts = ddos_sources.value_counts()

    # Print the source IPs and their counts
    print("Source IPs and their counts for DDoS traffic:")
    print(source_counts)

    # Add rules to block detected DDoS source IPs
    if not source_counts.empty:
        ip_to_block = source_counts.idxmax()
        ip_int = ip_to_int(ip_to_block)
        remove_arp_entry(switch_connection, p4info_helper, ip_int)
        logging.info(f"Removed ARP entry for IP with highest DDoS count: {ip_to_block}")

    # Save the results to a file
    source_counts.to_csv('ddos_sources.csv', header=['Count'])
    
def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def main(p4info_file_path, p4_binary_path, p4runtime_address, device_id):
    switch_connection, p4info_helper = connect_to_switch(
        p4info_file_path, p4_binary_path, p4runtime_address, device_id
    )
    try:
        add_default_forwarding_rules(switch_connection, p4info_helper)
      
        add_arp_entry(switch_connection, p4info_helper, "10.0.1.1", "00:00:00:00:01:01")
        add_arp_entry(switch_connection, p4info_helper, "10.0.1.2", "00:00:00:00:01:02")
        add_arp_entry(switch_connection, p4info_helper, "10.0.1.3", "00:00:00:00:01:03")
        add_arp_entry(switch_connection, p4info_helper, "10.0.1.4", "00:00:00:00:01:04")

        analyze_traffic(switch_connection, p4info_helper, file_path)

    except KeyboardInterrupt:
        logging.info("Shutting down.")
    finally:
        ShutdownAllSwitchConnections()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python controlplane.py <P4RUNTIME_ADDRESS> <DEVICE_ID>")
        sys.exit(1)

    p4runtime_address = sys.argv[1]
    device_id = int(sys.argv[2])

    main(P4INFO_FILE_PATH, P4_BINARY_PATH, p4runtime_address, device_id)
