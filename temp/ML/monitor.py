import time
import pandas as pd
from prediction import FirewallModel
from datetime import datetime
import logging
import json

# Configure logging
logging.basicConfig(
    filename='anomaly_detection.json',
    level=logging.INFO,
    format='%(message)s'  # Logs only the JSON data
)

class TrafficMonitor:
    def __init__(self, traffic_log_path, check_interval=1860):  # 1860 seconds = 31 minutes
        self.traffic_log_path = traffic_log_path
        self.ml_traffic_log_path = 'ml_traffic.csv'
        self.check_interval = check_interval
        self.model = FirewallModel(use_xgboost=True)
        self.last_processed_line = 0
        self.data = []  # Array to hold all anomalies

    def process_new_entries(self):
        try:
            start_time = time.perf_counter()

            # Read the original traffic log
            original_df = pd.read_csv(self.traffic_log_path)
            
            # Remove the 8th column (index 7) from the DataFrame
            modified_df = original_df.drop(original_df.columns[7], axis=1)
            
            # Map protocol to its corresponding number
            protocol_map = {'TCP': 6, 'UDP': 17}
            modified_df['protocol'] = modified_df['protocol'].map(protocol_map)
        
            # Save the modified DataFrame to ml_traffic.csv
            modified_df.to_csv(self.ml_traffic_log_path, index=False)
            
            # Read the modified CSV
            read_start = time.perf_counter() 
            df = pd.read_csv(self.ml_traffic_log_path, skiprows=self.last_processed_line)
            read_time = time.perf_counter() - read_start

            if df.empty:
                return

            # Model prediction
            pred_start = time.perf_counter()
            self.last_processed_line += len(df)
            flows = df.to_dict('records')

            confidences, predicted_classes = self.model.predict(flows)
            pred_time = time.perf_counter() - pred_start

            total_time = time.perf_counter() - start_time
            # logging.info(json.dumps({
            #     "Processing Times": {
            #         "Read Time": f"{read_time:.2f}s",
            #         "Prediction Time": f"{pred_time:.2f}s",
            #         "Total Time": f"{total_time:.2f}s"
            #     }
            # }))
            
            # Log anomalies and search in original traffic log
            for flow, confidence, pred_class in zip(flows, confidences, predicted_classes):
                if pred_class != "BENIGN":
                    anomaly_data = {
                        "Type": pred_class,
                        "Confidence": f"{confidence:.2%}",
                        "Source IP": flow.get('src_ip', 'N/A'),
                        "Destination IP": flow.get('dst_ip', 'N/A'),
                        "Timestamp": datetime.now().isoformat(),
                        "Process": flow.get('process', 'N/A'),
                        "Protocol": flow.get('protocol', 'N/A'),
                        "Source Port": flow.get('src_port', 'N/A'),
                        "Destination Port": flow.get('dst_port', 'N/A')
                    }

                    # Replace empty values with "NaN"
                    anomaly_data = {k: v if pd.notna(v) else "NaN" for k, v in anomaly_data.items()}

                    # Search for the same in the original traffic log
                    match = original_df[
                        (original_df['timestamp'] == flow.get('timestamp')) &
                        (original_df['src_ip'] == flow.get('src_ip')) &
                        (original_df['dst_ip'] == flow.get('dst_ip'))
                    ]
                    if not match.empty:
                        match = match.fillna("NaN")  # Replace NaN values with "NaN" as strings
                        matching_data = match.to_dict('records')
                    else:
                        matching_data = None

                    # Append the anomaly and matching data to the parent `data` array
                    self.data.append({
                        "anomaly": anomaly_data,
                        "processData": matching_data
                    })

                    # Write the updated data array to the log file
                    with open('anomaly_detection.json', 'w') as log_file:
                        json.dump({"data": self.data}, log_file, indent=4)

        except Exception as e:
            logging.error(json.dumps({"Error": str(e)}))

    def start_monitoring(self):
        # logging.info(json.dumps({"Message": "Starting traffic monitoring..."}))
        while True:
            self.process_new_entries()
            time.sleep(self.check_interval)

if __name__ == "__main__":
    TRAFFIC_LOG_PATH = "traffic_logs.csv"  # Replace with your CSV path
    monitor = TrafficMonitor(TRAFFIC_LOG_PATH)
    monitor.start_monitoring()
