import json
import time
import csv
import os
import psutil
from collections import defaultdict
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add after imports
headers = [
    # Basic flow identifiers
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
    'flow_duration', 'timestamp', 'process',
    
    # Packet statistics
    'tot_fwd_pkts', 'tot_bwd_pkts',
    'totlen_fwd_pkts', 'totlen_bwd_pkts',
    'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean', 'fwd_pkt_len_std',
    'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean', 'bwd_pkt_len_std',
    
    # Flow rates
    'flow_byts_s', 'flow_pkts_s',
    'fwd_pkts_s', 'bwd_pkts_s',
    
    # IAT statistics
    'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
    'fwd_iat_tot', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
    'bwd_iat_tot', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
    
    # Flags
    'fwd_psh_flags', 'bwd_psh_flags',
    'fwd_urg_flags', 'bwd_urg_flags',
    'fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt',
    'ack_flag_cnt', 'urg_flag_cnt', 'cwe_flag_count', 'ece_flag_cnt',
    
    # Packet lengths
    'pkt_len_min', 'pkt_len_max', 'pkt_len_mean', 'pkt_len_std', 'pkt_len_var',
    'fwd_header_len', 'bwd_header_len',
    'pkt_size_avg', 'fwd_seg_size_avg', 'bwd_seg_size_avg',
    
    # Bulk statistics
    'fwd_byts_b_avg', 'fwd_pkts_b_avg', 'fwd_blk_rate_avg',
    'bwd_byts_b_avg', 'bwd_pkts_b_avg', 'bwd_blk_rate_avg',
    
    # Subflow statistics
    'subflow_fwd_pkts', 'subflow_fwd_byts',
    'subflow_bwd_pkts', 'subflow_bwd_byts',
    
    # Window statistics
    'init_fwd_win_byts', 'init_bwd_win_byts',
    
    # Active/Idle statistics
    'active_mean', 'active_std', 'active_max', 'active_min',
    'idle_mean', 'idle_std', 'idle_max', 'idle_min',
    
    # Additional metrics
    'down_up_ratio'
]

def get_process_by_port(port):
    """Get process name using port number"""
    try:
        for conn in psutil.net_connections():
            if conn.laddr.port == port:
                try:
                    return psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        return "Unknown"
    except:
        return "Unknown"

# def get_process_by_port(port):
#     """
#     Get process name using port number with improved connection filtering and error handling
    
#     Args:
#         port (int): Port number to look up
        
#     Returns:
#         str: Process name or "Unknown"
#     """
#     try:
#         # Only look at internet connections (TCP/UDP)
#         for conn in psutil.net_connections(kind='inet'):
#             # Check both source and destination ports
#             if (hasattr(conn.laddr, 'port') and conn.laddr.port == port) or \
#                (hasattr(conn.raddr, 'port') and conn.raddr.port == port):
                
#                 if conn.pid:
#                     try:
#                         process = psutil.Process(conn.pid)
#                         if process.is_running():
#                             return process.name()
#                     except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#                         continue
                        
#         # Cache miss or no process found
#         return "Unknown"
        
#     except (psutil.Error, RuntimeError, AttributeError):
#         return "Unknown"

class EveJSONHandler(FileSystemEventHandler):
    def __init__(self, csv_file):
        self.csv_file = csv_file
        self.last_position = 0
        
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('eve.json'):
            self.process_new_lines()
            
    def process_new_lines(self):
        try:
            with open('log/eve.json', 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
                if new_lines:
                    events = [json.loads(line) for line in new_lines if line.strip()]
                    flows = process_traffic_data(events)
                    
                    if flows:
                        self.append_to_csv(flows)
        except Exception as e:
            print(f"Error processing new lines: {str(e)}")

    def append_to_csv(self, flows):
        file_exists = os.path.exists(self.csv_file)
        
        try:
            with open(self.csv_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                
                if not file_exists:
                    writer.writeheader()
                
                for flow_data in flows.values():
                    # Add process information
                    flow_data['process'] = get_process_by_port(flow_data['src_port'])
                    csv_data = prepare_flow_for_csv(flow_data)
                    writer.writerow(csv_data)
                    
        except Exception as e:
            print(f"Error appending to CSV: {str(e)}")

def monitor_eve_json(eve_file='log/eve.json', output_file='traffic_logs.csv'):
    """Monitor eve.json file continuously and update CSV in real-time"""
    print("Starting real-time traffic monitoring...")
    
    # Create an observer and handler
    event_handler = EveJSONHandler(output_file)
    observer = Observer()
    observer.schedule(event_handler, os.path.dirname(eve_file), recursive=False)
    
    try:
        observer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nMonitoring stopped by user")
    observer.join()

def calculate_statistics(values):
    """Calculate mean, std, min, max for a list of values"""
    if not values:
        return 0, 0, 0, 0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    std = variance ** 0.5
    return mean, std, min(values), max(values)

def process_traffic_data(events):
    # Enhanced flow tracking dictionary
    flows = defaultdict(lambda: {
        # Basic identifiers
        'src_ip': '',
        'dst_ip': '',
        'src_port': 0,
        'dst_port': 0,
        'protocol': 0,
        'timestamp_start': None,
        'timestamp_end': None,
        
        # Packet counts and sizes
        'tot_fwd_pkts': 0,
        'tot_bwd_pkts': 0,
        'totlen_fwd_pkts': 0,
        'totlen_bwd_pkts': 0,
        'fwd_pkt_lengths': [],
        'bwd_pkt_lengths': [],
        
        # Inter-arrival times
        'flow_iats': [],
        'fwd_iats': [],
        'bwd_iats': [],
        'last_fwd_time': None,
        'last_bwd_time': None,
        
        # TCP flags
        'fin_flag_cnt': 0,
        'syn_flag_cnt': 0,
        'rst_flag_cnt': 0,
        'psh_flag_cnt': 0,
        'ack_flag_cnt': 0,
        'urg_flag_cnt': 0,
        'cwe_flag_count': 0,
        'ece_flag_cnt': 0,
        
        # Window sizes
        'init_fwd_win_byts': 0,
        'init_bwd_win_byts': 0,
        
        # Active/Idle times
        'active_times': [],
        'idle_times': [],
        'last_active_time': None,
        'active_timeout': 5.0,  # 5 seconds timeout
        
        # Header lengths
        'fwd_header_len': 0,
        'bwd_header_len': 0,
    })
    
    for event in events:
        if event.get('event_type') == 'stats':
            continue
            
        flow_id = event.get('flow_id', '')
        flow = flows[flow_id]
        
        # Basic flow information
        flow['src_ip'] = event.get('src_ip', '')
        flow['dst_ip'] = event.get('dest_ip', '')
        flow['src_port'] = event.get('src_port', 0)
        flow['dst_port'] = event.get('dest_port', 0)
        flow['protocol'] = event.get('proto', '')
        
        # Timestamp processing
        timestamp = datetime.strptime(event['timestamp'].split('+')[0], '%Y-%m-%dT%H:%M:%S.%f')
        if not flow['timestamp_start']:
            flow['timestamp_start'] = timestamp
        flow['timestamp_end'] = timestamp
        
        # Packet direction and size processing
        is_forward = event.get('direction') == 'to_server'
        pkt_len = event.get('drop', {}).get('len', 0)
        
        if is_forward:
            flow['tot_fwd_pkts'] += 1
            flow['totlen_fwd_pkts'] += pkt_len
            flow['fwd_pkt_lengths'].append(pkt_len)
            if flow['last_fwd_time']:
                flow['fwd_iats'].append((timestamp - flow['last_fwd_time']).total_seconds())
            flow['last_fwd_time'] = timestamp
        else:
            flow['tot_bwd_pkts'] += 1
            flow['totlen_bwd_pkts'] += pkt_len
            flow['bwd_pkt_lengths'].append(pkt_len)
            if flow['last_bwd_time']:
                flow['bwd_iats'].append((timestamp - flow['last_bwd_time']).total_seconds())
            flow['last_bwd_time'] = timestamp
            
        # TCP flags processing
        if 'tcp' in event:
            tcp_flags = event['tcp']
            flow['fin_flag_cnt'] += int(tcp_flags.get('fin', False))
            flow['syn_flag_cnt'] += int(tcp_flags.get('syn', False))
            flow['rst_flag_cnt'] += int(tcp_flags.get('rst', False))
            flow['psh_flag_cnt'] += int(tcp_flags.get('psh', False))
            flow['ack_flag_cnt'] += int(tcp_flags.get('ack', False))
            flow['urg_flag_cnt'] += int(tcp_flags.get('urg', False))
            
        # Active/Idle time processing
        if flow['last_active_time']:
            gap = (timestamp - flow['last_active_time']).total_seconds()
            if gap > flow['active_timeout']:
                flow['idle_times'].append(gap)
            else:
                flow['active_times'].append(gap)
        flow['last_active_time'] = timestamp

    # Calculate final statistics for each flow
    for flow_id, flow in flows.items():
        duration = (flow['timestamp_end'] - flow['timestamp_start']).total_seconds()
        
        # Calculate packet length statistics
        fwd_len_stats = calculate_statistics(flow['fwd_pkt_lengths'])
        bwd_len_stats = calculate_statistics(flow['bwd_pkt_lengths'])
        
        # Add calculated metrics to flow
        flow['flow_duration'] = duration
        flow['fwd_pkt_len_mean'], flow['fwd_pkt_len_std'], flow['fwd_pkt_len_min'], flow['fwd_pkt_len_max'] = fwd_len_stats
        flow['bwd_pkt_len_mean'], flow['bwd_pkt_len_std'], flow['bwd_pkt_len_min'], flow['bwd_pkt_len_max'] = bwd_len_stats
        
        # Calculate rates
        flow['flow_byts_s'] = (flow['totlen_fwd_pkts'] + flow['totlen_bwd_pkts']) / duration if duration > 0 else 0
        flow['flow_pkts_s'] = (flow['tot_fwd_pkts'] + flow['tot_bwd_pkts']) / duration if duration > 0 else 0
        
        # IAT statistics
        flow['flow_iat_mean'], flow['flow_iat_std'], flow['flow_iat_min'], flow['flow_iat_max'] = calculate_statistics(flow['fwd_iats'] + flow['bwd_iats'])
        flow['fwd_iat_mean'], flow['fwd_iat_std'], flow['fwd_iat_min'], flow['fwd_iat_max'] = calculate_statistics(flow['fwd_iats'])
        flow['bwd_iat_mean'], flow['bwd_iat_std'], flow['bwd_iat_min'], flow['bwd_iat_max'] = calculate_statistics(flow['bwd_iats'])
        
        # Clean up temporary lists
        del flow['fwd_pkt_lengths']
        del flow['bwd_pkt_lengths']
        del flow['flow_iats']
        del flow['fwd_iats']
        del flow['bwd_iats']
        del flow['last_fwd_time']
        del flow['last_bwd_time']
        del flow['last_active_time']
        
    return flows

def prepare_flow_for_csv(flow_data):
    """
    Prepare flow data for CSV output by mapping flow metrics to CSV columns.
    
    Args:
        flow_data (dict): Dictionary containing flow metrics
        
    Returns:
        dict: Formatted data ready for CSV output
    """
    csv_data = {
        # Basic flow identifiers
        'src_ip': flow_data.get('src_ip', ''),
        'src_port': flow_data.get('src_port', ''),
        'dst_ip': flow_data.get('dst_ip', ''),
        'dst_port': flow_data.get('dst_port', ''),
        'protocol': flow_data.get('protocol', ''),
        'flow_duration': flow_data.get('flow_duration', 0.0),
        'timestamp': flow_data.get('timestamp', ''),
        'process': get_process_by_port(flow_data.get('src_port', 0)),

        # Packet statistics
        'tot_fwd_pkts': flow_data.get('tot_fwd_pkts', 0),
        'tot_bwd_pkts': flow_data.get('tot_bwd_pkts', 0),
        
        # Size statistics 
        'totlen_fwd_pkts': flow_data.get('totlen_fwd_pkts', 0),
        'totlen_bwd_pkts': flow_data.get('totlen_bwd_pkts', 0),
        'fwd_pkt_len_max': flow_data.get('fwd_pkt_len_max', 0),
        'fwd_pkt_len_min': flow_data.get('fwd_pkt_len_min', 0),
        'fwd_pkt_len_mean': flow_data.get('fwd_pkt_len_mean', 0.0),
        'fwd_pkt_len_std': flow_data.get('fwd_pkt_len_std', 0.0),
        'bwd_pkt_len_max': flow_data.get('bwd_pkt_len_max', 0),
        'bwd_pkt_len_min': flow_data.get('bwd_pkt_len_min', 0),
        'bwd_pkt_len_mean': flow_data.get('bwd_pkt_len_mean', 0.0),
        'bwd_pkt_len_std': flow_data.get('bwd_pkt_len_std', 0.0),
        'pkt_len_max': flow_data.get('pkt_len_max', 0),
        'pkt_len_min': flow_data.get('pkt_len_min', 0),
        'pkt_len_mean': flow_data.get('pkt_len_mean', 0.0),
        'pkt_len_std': flow_data.get('pkt_len_std', 0.0),
        'pkt_len_var': flow_data.get('pkt_len_var', 0.0),
        
        # Flow bytes statistics
        'fwd_header_len': flow_data.get('fwd_header_len', 0),
        'bwd_header_len': flow_data.get('bwd_header_len', 0),
        'flow_byts_s': flow_data.get('flow_byts_s', 0.0),
        'flow_pkts_s': flow_data.get('flow_pkts_s', 0.0),
        
        # IAT statistics
        'flow_iat_mean': flow_data.get('flow_iat_mean', 0.0),
        'flow_iat_max': flow_data.get('flow_iat_max', 0.0),
        'flow_iat_min': flow_data.get('flow_iat_min', 0.0),
        'flow_iat_std': flow_data.get('flow_iat_std', 0.0),
        'fwd_iat_tot': flow_data.get('fwd_iat_tot', 0),
        'fwd_iat_max': flow_data.get('fwd_iat_max', 0),
        'fwd_iat_min': flow_data.get('fwd_iat_min', 0),
        'fwd_iat_mean': flow_data.get('fwd_iat_mean', 0.0),
        'fwd_iat_std': flow_data.get('fwd_iat_std', 0.0),
        'bwd_iat_tot': flow_data.get('bwd_iat_tot', 0),
        'bwd_iat_max': flow_data.get('bwd_iat_max', 0),
        'bwd_iat_min': flow_data.get('bwd_iat_min', 0),
        'bwd_iat_mean': flow_data.get('bwd_iat_mean', 0.0),
        'bwd_iat_std': flow_data.get('bwd_iat_std', 0.0),
        
        # Flags statistics
        'fwd_psh_flags': flow_data.get('fwd_psh_flags', 0),
        'bwd_psh_flags': flow_data.get('bwd_psh_flags', 0),
        'fwd_urg_flags': flow_data.get('fwd_urg_flags', 0),
        'bwd_urg_flags': flow_data.get('bwd_urg_flags', 0),
        'fin_flag_cnt': flow_data.get('fin_flag_cnt', 0),
        'syn_flag_cnt': flow_data.get('syn_flag_cnt', 0),
        'rst_flag_cnt': flow_data.get('rst_flag_cnt', 0),
        'psh_flag_cnt': flow_data.get('psh_flag_cnt', 0),
        'ack_flag_cnt': flow_data.get('ack_flag_cnt', 0),
        'urg_flag_cnt': flow_data.get('urg_flag_cnt', 0),
        'ece_flag_cnt': flow_data.get('ece_flag_cnt', 0),
        
        # Additional packet counts
        'down_up_ratio': flow_data.get('down_up_ratio', 0.0),
        'pkt_size_avg': flow_data.get('pkt_size_avg', 0.0),
        'init_fwd_win_byts': flow_data.get('init_fwd_win_byts', 0),
        'init_bwd_win_byts': flow_data.get('init_bwd_win_byts', 0),
        
        # Active/Idle statistics
        'active_mean': flow_data.get('active_mean', 0.0),
        'active_std': flow_data.get('active_std', 0.0),
        'active_max': flow_data.get('active_max', 0.0),
        'active_min': flow_data.get('active_min', 0.0),
        'idle_mean': flow_data.get('idle_mean', 0.0),
        'idle_std': flow_data.get('idle_std', 0.0),
        'idle_max': flow_data.get('idle_max', 0.0),
        'idle_min': flow_data.get('idle_min', 0.0)
    }
    
    return csv_data

def upload_to_s3(data, bucket_name='trafficlogssih', region='us-east-1'):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_file = f'traffic_data_{timestamp}.csv'
    
    try:
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for flow_data in data.values():
                # Transform flow data to match CSV headers
                csv_data = prepare_flow_for_csv(flow_data)
                writer.writerow(csv_data)
                
        # Upload to S3
        s3_client = boto3.client(
            's3',
            region_name=region,
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
        )
        
        s3_path = f'logs/{timestamp[:8]}/{csv_file}'
        s3_client.upload_file(csv_file, bucket_name, s3_path)
        print(f"Data uploaded to S3: s3://{bucket_name}/{s3_path}")
            
    except Exception as e:
        print(f"Error uploading to S3: {str(e)}")
    finally:
        if os.path.exists(csv_file):
            os.remove(csv_file)

def save_locally(data, output_file='traffic_logs.csv'):
    """Save traffic data to local CSV file"""
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for flow_data in data.values():
                csv_data = prepare_flow_for_csv(flow_data)
                writer.writerow(csv_data)
                
        print(f"Data saved to {output_file}")
            
    except Exception as e:
        print(f"Error saving data locally: {str(e)}")

if __name__ == "__main__":
    print("Starting traffic monitoring with local storage...")
    monitor_eve_json()