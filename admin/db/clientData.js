import mongoose, { model } from 'mongoose';
const {Schema} = mongoose

const deviceInfoSchema = new Schema({
  device_name: String,
  os: String,
  public_ip: String,
  uptime: {
    days: Number,
    hours: Number,
    minutes: Number
  },
  cpu_info: {
    cpu_cores: Number,
    cpu_usage: Number
  },
  memory_info: {
    total_memory: Number,
    used_memory: Number,
    available_memory: Number
  }
});

const activeConnectionSchema = new Schema({
  pid: { type: Schema.Types.Mixed, default: 'N/A' },
  protocol: String,
  local_address: String,
  remote_address: String,
  status: String,
  process_name: String
});

const interfaceInfoSchema = new Schema({
    interface: String,
    status: String,
    addresses: [
      {
        type: { type: String, required: true },  // Type of address (MAC, IPv4, IPv6)
        address: { type: String, required: true } // Actual address (e.g., IP or MAC)
      }
    ],
    mtu: { type: String, default: 'N/A' }
  });

const networkUsageSchema = new Schema({
  time_of_report: String,
  bytes_sent: Number,
  bytes_received: Number,
  packets_sent: Number,
  packets_received: Number
});

const runningProcessSchema = new Schema({
  pid: Number,
  process_name: String,
  exe: String,
  app_name: String
});

const openPortSchema = new Schema({
    port: { type: Number, required: true },
    pid: { type: Number, required: true },
    process_name: { type: String, required: true }
  });

  const domainMappingSchema = new Schema({
    process_name: { type: String },
    domains: [{
      domain:String,
      timestamp:Date
    }]
  });

  const applicationDataSchema = new Schema({
    process: String,
    name: String,
    pid: Number,
    path: String,
    uptime: String,
    total_bytes_sent: Number,
    total_bytes_received: Number,
  });

const clientDataSchema = new Schema(
  {
    clientID: String,
    device_info: deviceInfoSchema,
    active_connections: [activeConnectionSchema],
    network_interfaces: [interfaceInfoSchema],
    network_usage: networkUsageSchema,
    running_processes: [runningProcessSchema],
    open_ports: [openPortSchema],
    domain_mapping: [domainMappingSchema],
    application_data: [applicationDataSchema]
  },
  { timestamps: true }
);

export async function getStaticData(clientID) {
  try{
    let data = await ClientData.findOne({clientID: clientID})
    return data;
  }catch (error) {
    console.log('Error finding static data:', error);
    return false;
  }

}

export async function upsertStaticData(clientID , staticInfo){
  try{
      
      let userDeviceData = await ClientData.findOne({ clientID: clientID });
      if (userDeviceData) {
          // If document exists, update it with the new staticInfo data
          userDeviceData.device_info = staticInfo.device_info || userDeviceData.device_info;
          userDeviceData.active_connections = staticInfo.active_connections || userDeviceData.active_connections;
          userDeviceData.network_interfaces = staticInfo.network_interfaces || userDeviceData.network_interfaces;
          userDeviceData.network_usage = staticInfo.network_usage || userDeviceData.network_usage;
          userDeviceData.running_processes = staticInfo.running_processes || userDeviceData.running_processes;
          userDeviceData.open_ports = staticInfo.open_ports || userDeviceData.open_ports;
          userDeviceData.domain_mapping = staticInfo.domain_mapping || userDeviceData.domain_mapping;
          userDeviceData.application_data = staticInfo.application_data || userDeviceData.application_data
          // Save the updated document
          await userDeviceData.save();
          console.log('User device data updated successfully.');
        } else {
          // If document doesn't exist, create a new document
          const newUserDeviceData = new ClientData({
            clientID: clientID,
            device_info: staticInfo.device_info,
            active_connections: staticInfo.active_connections,
            network_interfaces: staticInfo.network_interfaces,
            network_usage: staticInfo.network_usage,
            running_processes: staticInfo.running_processes,
            open_ports: staticInfo.open_ports,
            domain_mapping: staticInfo.domain_mapping,
            application_data: staticInfo.application_data
          });
    
          // Save the new document
          await newUserDeviceData.save();
          console.log('New user device data created successfully.');
        }
        return true;
      } catch (error) {
          console.error('Error upserting user device data:', error);
          return false;
        }
}

const ClientData = model('ClientData', clientDataSchema);

export default ClientData;
