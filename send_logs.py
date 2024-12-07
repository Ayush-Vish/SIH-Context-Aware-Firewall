import json
import time
import csv
import os
import boto3
from collections import defaultdict
from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv()

def process_traffic_data(events):
    # Dictionary to store aggregated flow data
    flows = defaultdict(lambda: {
        'src_port': 0,
        'dest_port': 0,
        'nat_src_port': 0,
        'nat_dest_port': 0, 
        'action': '',
        'bytes': 0,
        'bytes_sent': 0,
        'bytes_received': 0,
        'packets': 0,
        'elapsed_time': 0,
        'pkts_sent': 0,
        'pkts_received': 0
    })
    
    for event in events:
        if event.get('event_type') == 'stats':
            continue

        flow_id = event.get('flow_id', '')
        flow = flows[flow_id]
        
        # Update basic port info from any event type
        flow['src_ip'] = event.get('src_ip', '')
        flow['dest_ip'] = event.get('dest_ip', '')
        flow['src_port'] = event.get('src_port', 0)
        flow['dest_port'] = event.get('dest_port', 0)
        
        # Update action based on event type
        if 'alert' in event:
            flow['action'] = event['alert'].get('action', 'unknown')
        elif 'drop' in event:
            flow['action'] = 'drop'
        elif 'flow' in event and event.get('flow', {}).get('action'):
            flow['action'] = event['flow']['action']
        else:
            flow['action'] = 'allow'  # Set default action to 'allow'
            
        # Update metrics if flow data exists
        if 'flow' in event:
            flow_data = event['flow']
            flow['bytes_sent'] = flow_data.get('bytes_toserver', 0)
            flow['bytes_received'] = flow_data.get('bytes_toclient', 0)
            flow['bytes'] = flow['bytes_sent'] + flow['bytes_received']
            flow['pkts_sent'] = flow_data.get('pkts_toserver', 0)
            flow['pkts_received'] = flow_data.get('pkts_toclient', 0)
            flow['packets'] = flow['pkts_sent'] + flow['pkts_received']
            
            # Calculate elapsed time
            if 'start' in flow_data:
                start_time = flow_data['start']
                try:
                    start_seconds = time.mktime(time.strptime(start_time.split('+')[0], '%Y-%m-%dT%H:%M:%S'))
                    flow['elapsed_time'] = int(time.time() - start_seconds)
                except:
                    flow['elapsed_time'] = 0
        # Handle non-flow events
        else:
            # Update packet counts for non-flow events
            flow['packets'] += 1
            if event.get('direction') == 'to_server':
                flow['pkts_sent'] += 1
            elif event.get('direction') == 'to_client': 
                flow['pkts_received'] += 1
                
            # Update bytes from drop events
            if 'drop' in event:
                drop_data = event['drop']
                flow['bytes'] += drop_data.get('len', 0)
                if event.get('direction') == 'to_server':
                    flow['bytes_sent'] += drop_data.get('len', 0)
                elif event.get('direction') == 'to_client':
                    flow['bytes_received'] += drop_data.get('len', 0)

    return flows

def upload_to_s3(data, bucket_name='trafficlogssih', region='us-east-1'):
    """Upload traffic data as CSV to AWS S3"""
    
    # Create unique filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_file = f'traffic_data_{timestamp}.csv'
    
    headers = ['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 
                'NAT Source Port', 'NAT Destination Port', 'Action', 'Bytes', 
                'Bytes Sent', 'Bytes Received', 'Packets', 'Elapsed Time (sec)', 
                'pkts_sent', 'pkts_received']
    
    try:
        # Create CSV file locally first
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for flow_data in data.values():
                writer.writerow({
                    'Source IP': flow_data['src_ip'],
                    'Destination IP': flow_data['dest_ip'],
                    'Source Port': flow_data['src_port'],
                    'Destination Port': flow_data['dest_port'],
                    'NAT Source Port': flow_data['nat_src_port'],
                    'NAT Destination Port': flow_data['nat_dest_port'],
                    'Action': flow_data['action'],
                    'Bytes': flow_data['bytes'],
                    'Bytes Sent': flow_data['bytes_sent'],
                    'Bytes Received': flow_data['bytes_received'],
                    'Packets': flow_data['packets'],
                    'Elapsed Time (sec)': flow_data['elapsed_time'],
                    'pkts_sent': flow_data['pkts_sent'],
                    'pkts_received': flow_data['pkts_received']
                })

        # Initialize S3 client
        s3_client = boto3.client(
            's3',
            region_name=region,
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
        )

        # Upload file to S3
        s3_path = f'logs/{timestamp[:8]}/{csv_file}'  # Organize by date
        s3_client.upload_file(
            csv_file, 
            bucket_name, 
            s3_path,
            ExtraArgs={'ContentType': 'text/csv'}
        )
        
        print(f"Data uploaded to S3: s3://{bucket_name}/{s3_path}")
            
    except Exception as e:
        print(f"Error uploading to S3: {str(e)}")
    finally:
        # Clean up local CSV file
        if os.path.exists(csv_file):
            os.remove(csv_file)

def monitor_eve_json(eve_file='log/eve.json', interval=30):
    """Monitor eve.json file, send all content, and clear it every interval seconds"""
    
    while True:
        try:
            # Check if file exists and has content
            if os.path.exists(eve_file) and os.path.getsize(eve_file) > 0:
                # Read entire file
                with open(eve_file, 'r') as f:
                    lines = f.readlines()
                
                if lines:
                    # Process all events
                    events = [json.loads(line) for line in lines if line.strip()]
                    flows = process_traffic_data(events)
                    
                    # Upload to S3
                    if flows:
                        upload_to_s3(flows)
                    
                    # Clear the file
                    open(eve_file, 'w').close()
                    print(f"Cleared {eve_file}")
            
            # Wait for next interval
            time.sleep(interval)
                
        except Exception as e:
            print(f"Error processing eve.json: {str(e)}")
            time.sleep(interval)

if __name__ == "__main__":
    # Check for AWS credentials
    if not os.environ.get('AWS_ACCESS_KEY_ID') or not os.environ.get('AWS_SECRET_ACCESS_KEY'):
        print("Error: AWS credentials not found in environment variables")
        print("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
        exit(1)
        
    print("Starting traffic monitoring with S3 upload...")
    monitor_eve_json()