import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt

# Load the new dataset
ntraffic_data = pd.read_csv(r"/home/p4/tutorials/exercises/SwitchTree/p4cap.csv")

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
X_new = X_new.values


# Load the trained model
model = joblib.load(r'/home/p4/tutorials/exercises/SwitchTree/udp_rf_model_5trees.sav')


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
ddos_entries = ntraffic_data[ntraffic_data['Predictions'] == 1]  # Assuming 1 represents DDoS in your model

# Extract the source IPs of the DDoS traffic
ddos_sources = ddos_entries['Source IP']

# Count the frequency of each source IP
source_counts = ddos_sources.value_counts()

# Print the source IPs and their counts
print("Source IPs and their counts for DDoS traffic:")
print(source_counts)

# Save the results to a file if needed
source_counts.to_csv('ddos_sources.csv', header=['Count'])
