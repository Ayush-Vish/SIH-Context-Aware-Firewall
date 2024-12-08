import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';


const ruleSchema = new mongoose.Schema({
    ruleID: { type: String, required: true, unique: true },  // Unique rule identifier
    clientID: { type: String, required: true},  // ID of the client
    adminID: { type: String, required: true},  // ID of the admin
    protocol: { type: [String], enum: ['TCP', 'UDP']},  // Multiple protocols
    port: { type: [String]},  // Multiple ports
    applicationName: { type: [String]},  // Multiple application names
    domain: { type: [String]},  // Multiple domains
    ip: { type: [String]},  // Multiple IPs and subnets
    geolocationBlockedCountries: { type: [String]},  // List of countries to block (array)
    direction: { type: String, enum: ['incoming', 'outgoing', 'both']},  // Direction of traffic
    action: { type: String, enum: ['allow', 'deny']},  // Action to take (allow or deny)
    status: { type: String, enum: ['active', 'inactive']},  // Current status of the rule
    description: { type: String},  // Description of the rule
    scheduleStart: { type: Number, min: 0, max: 24},  // Start time of rule (in hours)
    scheduleEnd: { type: Number, min: 0, max: 24}  // End time of rule (in hours)
  },{timestamps:true});



export const Rule = mongoose.model("Rule", ruleSchema);
