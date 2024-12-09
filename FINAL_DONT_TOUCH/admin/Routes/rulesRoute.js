import { Router } from "express";
import { getIO } from "../socket.js";
import { clientMap } from "../index.js";
import { Client } from "../db/client.js";
import { generateNetshCommand } from "../utils/command";

const router = Router();

router.post("/add-app-rules", async (req, res) => {
    const { clientID, rules } = req.body;

    // Validate input
    if (!clientID || !rules || !Array.isArray(rules)) {
        return res.status(400).send({
            message: "Invalid input. Provide clientID, appName, listType (whitelist/blocklist), and rules.",
        });
    }

    try {
        const client = await Client.findOne({ clientID: clientID });
        if (!client) {
            return res.status(404).send({ message: "Client not found.", clientID });
        }

        for (const rule of rules) {
            const { appName } = rule;
            let app = client.applications.find((app) => app.appName === appName);
            if (!app) {
                // Create a new application entry if it doesn't exist
                app = { appName, whitelist: [], blocklist: [], active_list: null };
                client.applications.push(app);
            }

            app.blocklist.push(rule);

            // Generate the netsh command
            const commands = await generateNetshCommand("add", rule);

            // Save the client with the new rule
            await client.save();

            const io = getIO();
            const clientInfo = clientMap.get(clientID);

            if (clientInfo) {
                const socketId = clientInfo.socketId;
                io.to(socketId).emit("v2", { commands });
            } else {
                console.error(`Client not found in clientMap: ${clientID}`);
            }
        }

        res.send({
            message: "Rules added and sent to client",
            clientID,
            rules,
        });
    } catch (error) {
        console.error(`Error adding rules for client ${clientID}:`, error);
        res.status(500).send({
            message: "An error occurred while adding rules.",
            error: error.message,
        });
    }
});

router.post("/block-domain", async (req, res) => {
      const { clientID, rules } = req.body;
  
      // Validate input
      if (!clientID || !rules || !Array.isArray(rules)) {
          return res.status(400).send({
              message: "Invalid input. Provide clientID and rules.",
          });
      }
  
      try {
          const client = await Client.findOne({ clientID: clientID });
          if (!client) {
              return res.status(404).send({ message: "Client not found.", clientID });
          }
  
          for (const rule of rules) {
              const commands = await generateNetshCommand("add", rule);
  
              client.global_rules.push(rule);
              await client.save();
  
              const clientInfo = clientMap.get(clientID);
              const io = getIO();
  
              if (clientInfo) {
                  const socketId = clientInfo.socketId;
                  io.to(socketId).emit("v2", { commands });
              } else {
                  console.error(`Client not found in clientMap: ${clientID}`);
              }
          }
  
          res.send({ message: "Rules added and sent to client", clientID, rules });
      } catch (error) {
          console.error(`Error adding domain rules for client ${clientID}:`, error);
          res.status(500).send({
              message: "An error occurred while adding domain rules.",
              error: error.message,
          });
      }
  });
  
  router.post("/block-port", async (req, res) => {
      const { clientID, rule } = req.body;
  
      // Validate input
      if (!clientID || !rule) {
          return res.status(400).send({
              message: "Invalid input. Provide clientID and rule.",
          });
      }
  
      try {
          const client = await Client.findById(clientID);
          if (!client) {
              return res.status(404).send({ message: "Client not found.", clientID });
          }
  
          const clientInfo = clientMap.get(clientID);
          const io = getIO();
  
          if (clientInfo) {
              const socketId = clientInfo.socketId;
              console.log(socketId);
              console.log("Sending port block request to client", rule);
  
              // Add the rule to the global blocklist
              client.global_blocklist.push(rule);
              await client.save();
  
              io.to(socketId).emit("block_port", { rule });
              res.send({ message: "Port blocked and sent to client", clientID, rule });
          } else {
              res.status(404).send({ message: "Client not found", clientID });
          }
      } catch (error) {
          console.error(`Error blocking port for client ${clientID}:`, error);
          res.status(500).send({
              message: "An error occurred while blocking port.",
              error: error.message,
          });
      }
  });
  
  router.get("/get-rules/:clientID", async (req, res) => {
      const { clientID } = req.params;
  
      try {
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
      } catch (error) {
          console.error(`Error getting rules for client ${clientID}:`, error);
          res.status(500).send({
              message: "An error occurred while getting rules.",
              error: error.message,
          });
      }
  });
  
  router.delete("/delete-rule", async (req, res) => {
      const { clientID, appName, ruleName } = req.body;
  
      // Validate input
      if (!clientID || !appName || !ruleName) {
          return res.status(400).send({
              message: "Invalid input. Provide clientID, appName, and ruleName.",
          });
      }
  
      try {
          const clientInfo = clientMap.get(clientID);
          const io = getIO();
  
          if (clientInfo) {
              const socketId = clientInfo.socketId;
              console.log(socketId);
              console.log("Sending delete rule request to client", ruleName);
  
              // Delete the rule from the database
              const client = await Client.findById(clientID);
              if (!client) {
                  return res.status(404).send({ message: "Client not found.", clientID });
              }
  
              // Find the application
              let app = client.applications.find((app) => app.appName === appName);
              if (!app) {
                  return res.status(404).send({ message: "Application not found.", appName });
              }
  
              // Remove the rule from both lists
              app.whitelist = app.whitelist.filter((rule) => rule.rule_name !== ruleName);
              app.blocklist = app.blocklist.filter((rule) => rule.rule_name !== ruleName);
              await client.save();
  
              io.to(socketId).emit("delete_rule", { ruleName });
              res.send({
                  message: "Rule deleted and sent to client",
                  clientID,
                  ruleName,
              });
          } else {
              res.status(404).send({ message: "Client not found", clientID });
          }
      } catch (error) {
          console.error(`Error deleting rule for client ${clientID}:`, error);
          res.status(500).send({
              message: "An error occurred while deleting rule.",
              error: error.message,
          });
      }
  });
export default router;