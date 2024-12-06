import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';


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
