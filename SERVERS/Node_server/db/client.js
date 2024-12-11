import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
const ruleSchema = new mongoose.Schema({
  rule_name: { type: String, required: true },
  appName: { type: String, required: false }, // Link to the application
  domain: [{ type: String }], // Optional for domain rules
  app_path: { type: String , required:false }, // Optional, executable path for domain rules
  ip_addresses:[{
    type:String
  }],
  applied_to:[{
    type:String
  }],
  created_by:{
    type:String
  },

  ports: [{ type: Number }], // Optional, ports for the rule
  protocol: { type: String, enum: ["TCP", "UDP"] }, 
  action: { type: String, enum: ["allow", "block"], default: "block" },
  direction: { type: String, enum: ["inbound", "outbound"], required: true },
  status: { type: String, enum: ["active", "inactive"], default: "active" }
});

const appSchema = new mongoose.Schema({
  appName: { type: String, required: true },
  whitelist: [ruleSchema],
  blocklist: [ruleSchema],
  active_list: {
      type: String,
      enum: ["whitelist", "blocklist"],
      default: "blocklist"
  }
});

const clientSchema = new mongoose.Schema({
  clientID: { 
      type: String,  
      unique: true, 
  },
  adminID: { 
      type: String,
  },
  mac_addresses: [String],
  created_at: { type: Date, default: Date.now },
  last_seen: { type: Date },
  applications: [appSchema],
  global_rules: [ruleSchema],
});

export const findClientByMAC = async (macAddresses) => {
    try {
        // Search for the client by checking if any of the MAC addresses match the stored ones
        const client = await Client.findOne({
            mac_addresses: { $in: macAddresses }
        });

        // If client is found, return it
        if (client) {
            client.last_seen = new Date();
            await client.save(); // Save updated client data
            return client;
        } else {
            return null; // Return null if no client is found
        }
    } catch (err) {
        console.error("Error finding client:", err);
        throw err;
    }
};

export const createClientByMAC = async (macAddresses) => {
    try {
        // Create a new client
        const clientID = uuidv4();
        const newClient = new Client({
            clientID: clientID,
            mac_addresses: macAddresses,
            last_seen: new Date(),
        });

        await newClient.save(); // Save the new client to the database
        return newClient; // Return the newly created client
    } catch (err) {
        console.error("Error creating Client:", err);
        throw err;
    }
};

export const Client = mongoose.model("Client", clientSchema);