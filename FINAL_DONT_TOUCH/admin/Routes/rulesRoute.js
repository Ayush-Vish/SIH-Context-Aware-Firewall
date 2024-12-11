import { Router } from "express";
import { getSocket } from "../socket/init.js";
import { clientMap } from "../server.js";
import { Client, Rule } from "../db/client.js";
import { generateNetshCommand } from "../utils/command.js";

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

            const io = getSocket();
            const clientInfo = clientMap.get(clientID);

            if (clientInfo) {
                const socketId = clientInfo.socketID;
                io.to(socketId).emit("command", { commands , rule_type : "app_rules" });
                const newRule = new Rule(rule);
                await newRule.save();

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
              const io = getSocket();
  
              if (clientInfo) {
                  const socketId = clientInfo.socketID;
                  io.to(socketId).emit("command", { commands , rule_type : "domain_rules" });
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
      const { clientID, rules } = req.body;
  
      // Validate input
      if (!clientID || !rules || !Array.isArray(rules)) {
          return res.status(400).send({
              message: "Invalid input. Provide clientID and rule.",
          });
      }
  
      try {
          const client = await Client.findOne({clientID});
          if (!client) {
              return res.status(404).send({ message: "Client not found.", clientID });
          }
  
          const clientInfo = clientMap.get(clientID);
          const io =await  getSocket();
          console.log(clientInfo);
          if (clientInfo) {
              const socketId = clientInfo.socketID;
              console.log(socketId);
              console.log("Sending port block request to client", rules);
            for (const rule of rules)  {
                  // Generate the netsh command
                  const commands = await generateNetshCommand("add", rule);
                  // Save the client with the new rule
                  await client.global_rules.push(rule);
                  await client.save();
                  console.log(commands , "commands" , socketId);
                  io.to(socketId).emit("command", { commands , rule_type : "port_rules" });
            }
              // Add the rule to the global blocklist
             
              res.send({ message: "Port blocked and sent to client", clientID, rules });
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
          const io = getSocket();
  
          if (clientInfo) {
              const socketId = clientInfo.socketID;
              console.log(socketId);
              console.log("Requesting rules from client", clientID);
              const commands=[
                  [`netsh` , `advfirewall` , `firewall` , `show` , `rule` , `name=all`]
              ]
              io.to(socketId).emit("command", { commands  , rule_type : "get_rules" });
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
      if (!clientID || !ruleName) {
          return res.status(400).send({
              message: "Invalid input. Provide clientID and ruleName.",
          });
      }
  
      try {
          const clientInfo = clientMap.get(clientID);
          const io = getSocket();
  
          if (clientInfo) {
              const socketId = clientInfo.socketID;
              console.log(socketId);
              console.log("Sending delete rule request to client", ruleName);
  
              // Delete the rule from the database
              const client = await Client.findOne({clientID});
              if (!client) {
                  return res.status(404).send({ message: "Client not found.", clientID });
              }
  
              let ruleFound = false;
  
              // Check if the rule is a global rule
              client.global_rules = client.global_rules.filter((rule) => {
                  if (rule.rule_name === ruleName) {
                      ruleFound = true;
                      return false;
                  }
                  return true;
              });
  
              if (!ruleFound && appName) {
                  // Find the application
                  let app = client.applications.find((app) => app.appName === appName);
                  if (!app) {
                      return res.status(404).send({ message: "Application not found.", appName });
                  }
  
                  // Remove the rule from both lists
                  app.whitelist = app.whitelist.filter((rule) => rule.rule_name !== ruleName);
                  app.blocklist = app.blocklist.filter((rule) => rule.rule_name !== ruleName);
              }
  
              await client.save();
              const commands = [
                  [`netsh` , `advfirewall` , `firewall` , `delete` , `rule` , `name=${ruleName}`]
              ]
              io.to(socketId).emit("command", { commands  , rule_type: "delete_rule" });
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