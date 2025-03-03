import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

const alertSchema = new mongoose.Schema({
  message: { 
    type: String, 
    required: true
  },
  clientID: { 
    type: String,  
  }
},{ timestamps: true });

export const Alert = mongoose.model("Alert", alertSchema);

export const createAlertByMessage = async (message , clientID) => {
    try {
        const newAlert = new Alert({
            message: message,
            clientID: clientID
        });

        await newAlert.save(); // Save the new admin to the database
        return newAlert; // Return the newly created admin
    } catch (err) {
        console.error("Error creating alert:", err);
        throw err;
    }
};

export const findAlertsByAdmin = async (clientIDS) => {
    try {
      // Query the database for alerts where clientID is in the provided array
      const alerts = await Alert.find({
        clientID: { $in: clientIDS }
      }).sort({ createdAt: -1 }); // Optional: Sort by newest first
  
      return alerts; // Return the matching alerts
    } catch (err) {
      console.error("Error finding alerts:", err);
      throw err;
    }
};
