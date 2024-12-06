import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

const adminSchema = new mongoose.Schema({
  adminID: { 
    type: String, 
    required: true, 
    unique: true, 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
  },
  password: { 
    type: String, 
    required: true, 
  },
  clientID: [{ 
    type: String,  
  }]
},{ timestamps: true });

export const Admin = mongoose.model("Admin", adminSchema);

export const findAdminByEmail = async (email) => {
    try {
        // Search for the admin by email
        const admin = await Admin.findOne({
            email: email
        });

        if (admin) {
            return admin;
        } else {
            return null; // Return null if no admin is found
        }
    } catch (err) {
        console.error("Error finding admin:", err);
        throw err;
    }
};

export const createAdminByEmail = async (email , password) => {
    try {
        // Create a new admin
        const adminID = uuidv4();
        const newAdmin = new Admin({
            adminID: adminID,
            email: email,
            password: password,
            clientID: []
        });

        await newAdmin.save(); // Save the new admin to the database
        return newAdmin; // Return the newly created admin
    } catch (err) {
        console.error("Error creating Admin:", err);
        throw err;
    }
};
