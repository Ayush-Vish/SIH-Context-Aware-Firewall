import { Router } from "express";
import axios from "axios";
import { getIO } from "../socket.js";
import { clientMap } from "../index.js";
import { Client } from "../db/client.js";
const router = Router();
/**
 * TODO : Save the rules in the DB as well for all controllers.
 *  
 */
router.post("/add-app-rules", async (req, res) => {
    console.log("Request to add rule", req.body);
    const { clientID, rule } = req.body;
    const clientInfo = clientMap.get(clientID);
    console.log(clientID, rule);
    const io = getIO();

    if (clientInfo) {
        const socketId = clientInfo.socketId;
        console.log(socketId);

        // Save the rule in the database
        const newRule = new Rule({
            clientID,
            type: 'application',
            rule_name: rule.rule_name,
            app_path: rule.app_path,
            direction: rule.direction,
            ports: rule.ports,
            action: rule.action,
            created_by: rule.created_by,
            ip_addresses: rule.ip_addresses
        });

        await newRule.save();

        io.to(socketId).emit("new_app_rule", { rule });

        res.send({ message: "Rule added and sent to client", clientID, rule });
    } else {
        console.log("Client not found", clientID);
        res.status(404).send({ message: "Client not found", clientID });
    }
});

router.post("/block-domain", async (req, res) => {
    const { clientID, rule } = req.body;
    const clientInfo = clientMap.get(clientID);
    const io = getIO();
    if (clientInfo) {
        const socketId = clientInfo.socketId;
        console.log(socketId);
        console.log("Sending domain block request to client", rule);

        // Save the rule in the database
        const newRule = new Rule({
            clientID,
            type: 'domain',
            rule_name: rule.rule_name,
            domain: rule.domain,
            direction: rule.direction,
            action: rule.action,
            created_by: rule.created_by,
            ip_addresses: rule.ip_addresses
        });

        await newRule.save();

        io.to(socketId).emit("block_domain", { rule });
        res.send({ message: "Domain blocked and sent to client", clientID, rule });
    } else {
        res.status(404).send({ message: "Client not found", clientID });
    }
});

router.post("/block-port", async (req, res) => {
    const { clientID, rule } = req.body;
    const clientInfo = clientMap.get(clientID);
    const io = getIO();
    if (clientInfo) {
        const socketId = clientInfo.socketId;
        console.log(socketId);
        console.log("Sending port block request to client", rule);

        // Save the rule in the database
        const newRule = new Rule({
            clientID,
            type: 'port',
            rule_name: rule.rule_name,
            ports: rule.ports,
            direction: rule.direction,
            action: rule.action,
            created_by: rule.created_by,
            ip_addresses: rule.ip_addresses
        });

        await newRule.save();

        io.to(socketId).emit("block_port", { rule });
        res.send({ message: "Port blocked and sent to client", clientID, rule });
    } else {
        res.status(404).send({ message: "Client not found", clientID });
    }
});

router.get("/get-rules/:clientID", async (req, res) => {
    const { clientID } = req.params;
    const clientInfo = clientMap.get(clientID);
    const io = getIO();
    if (clientInfo) {
        const socketId = clientInfo.socketId;
        console.log(socketId);
        console.log("Requesting rules from client", clientID);
        io.to(socketId).emit("get_rules", { clientID });
        res.send({ message: "Request sent to client", clientID });
    } else {
        res.status(404).send({ message: "Client not found", clientID });
    }
});

router.delete("/delete-rule", async (req, res) => {
    const { clientID, ruleName } = req.body;
    const clientInfo = clientMap.get(clientID);
    const io = getIO();
    if (clientInfo) {
        const socketId = clientInfo.socketId;
        console.log(socketId);
        console.log("Sending delete rule request to client", ruleName);

        // Delete the rule from the database
        await Rule.deleteOne({ clientID, rule_name: ruleName });

        io.to(socketId).emit("delete_rule", { ruleName });
        res.send({ message: "Rule deleted and sent to client", clientID, ruleName });
    } else {
        res.status(404).send({ message: "Client not found", clientID });
    }
});

router.post("/toggle-list", async (req, res) => {
    const { clientID, appName, listType, rules } = req.body;

    // Validate input
    if (!clientID || !appName || !listType || !["whitelist", "blacklist"].includes(listType)) {
        return res.status(400).send({ message: "Invalid input. Provide clientID, appName, listType (whitelist/blacklist), and rules." });
    }
    const client = await Client.findById(clientID);
    if (!client) {
        return res.status(404).send({ message: "Client not found.", clientID });
    }

    const clientInfo = clientMap.get(clientID);
    const io = getIO();

    if (clientInfo) {
        const socketId = clientInfo.socketId;

        // Check if the list type is already active
        if (client.active_list === listType) {
            return res.status(200).send({
                message: `${listType} is already active for the client.`,
                activeList: client.active_list,
            });
        }

        // Toggle the list type and deactivate the other one
        client.active_list = listType;
        client.active_rules = [{ appName, rules }];
        await client.save();

        console.log(`Switching to ${listType} for client ${clientID}.`);

        // Emit the toggle action with the list to the client via WebSocket
        io.to(socketId).emit("toggle_list", { listType, appName, rules });

        return res.status(200).send({
            message: `${listType} activated and sent to client.`,
            clientID,
            listType,
            rules,
        });
    } else {
        return res.status(404).send({ message: "Client not found.", clientID });
    }
});
export default router