import { Router } from "express";
import { getIO } from "../socket.js";
import { clientMap } from "../index.js";
import { Client } from "../db/client.js";
import { generateNetshCommand } from "../utils/command.js";

const router = Router();

/**
 * body: clientID (String)
 * body: rules (Array)
 * rules:{
 *         rule_name: String,
 *        appName: String,
 *       domain: String,
 *      app_path: String,
 *       ports: [Number],
 *       action : String, enum ["allow", "block"]
 *         direction: String, enum ["inbound", "outbound"]
 * }
 */

router.post("/add-app-rules", async (req, res) => {
  const { clientID, rules , listType } = req.body;

  // Validate input
  if (!clientID || !rules || !Array.isArray(rules) || !listType) {
    return res
      .status(400)
      .send({
        message:
          "Invalid input. Provide clientID, appName, listType (whitelist/blocklist), and rule.",
      });
  }

  const client = await Client.findById(clientID);
  if (!client) {
    return res.status(404).send({ message: "Client not found.", clientID });
  }
  rules.forEach(async(rule )=> {
    const { appName } = rule;
    client.applications.forEach((app) => {
        if (app.appName === appName) {
            if (listType === "whitelist") {
            app.whitelist.push(rule);
            } else {
            app.blocklist.push(rule);
            }
        }
    })
    await client.save();
  })
    const io = getIO();


    
    const clientInfo = clientMap.get(clientID);
    
  if (clientInfo) {
    const socketId = clientInfo.socketId;
    io.to(socketId).emit("update_rules", { listType, rules });

    res.send({
      message: "Rule added and sent to client",
      clientID,

      listType,
      rules,
    });
  } else {
    res.status(404).send({ message: "Client not found.", clientID });
  }
});

/***
 * 
 * 
 * This route is used to add a rule to the global blocklist of the client
 * body: clientID (String)
 * body: rule (Object)
 * rule:{
 *      rule_name: String,
 *      domain: String,
 *      direction: String, enum ["inbound", "outbound"]
 *      action : String, enum ["allow", "block"]
 *      ports: [Number]
 */


router.post("/block-domain", async (req, res) => {
  const { clientID, rule } = req.body;
  const clientInfo = clientMap.get(clientID);
  const io = getIO();
  if (clientInfo) {
    const socketId = clientInfo.socketId;
    console.log(socketId);
    console.log("Sending domain block request to client", rule);

    // Save the rule in the database
    const client = await Client.findById(clientID);
    if (!client) {
      return res.status(404).send({ message: "Client not found.", clientID });
    }

    // Add the rule to the global blocklist
    client.global_blocklist.push(rule);
    await client.save();

    io.to(socketId).emit("block_domain", { rule });
    res.send({ message: "Domain blocked and sent to client", clientID, rule });
  } else {
    res.status(404).send({ message: "Client not found", clientID });
  }
});

/**
 * body: clientID (String)
 * body: rule (Object)
 * rule:{
 *      rule_name: String,
 *      ports: [Number]
 *      protocol: String, enum ["tcp", "udp" ,"both"]
 *      action : String, enum ["allow", "block"]
 *      direction: String, enum ["inbound", "outbound"]
 */


router.post("/block-port", async (req, res) => {
  const { clientID, rule } = req.body;
  const clientInfo = clientMap.get(clientID);
  const io = getIO();
  if (clientInfo) {
    const socketId = clientInfo.socketId;
    console.log(socketId);
    console.log("Sending port block request to client", rule);

    // Save the rule in the database
    const client = await Client.findById(clientID);
    if (!client) {
      return res.status(404).send({ message: "Client not found.", clientID });
    }

    // Add the rule to the global blocklist
    client.global_blocklist.push(rule);
    await client.save();

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


/**
 * 
 * body: clientID (String)
 * body: ruleName (String)
 */

router.delete("/delete-rule", async (req, res) => {
  const { clientID, appName, ruleName } = req.body;
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
      return res
        .status(404)
        .send({ message: "Application not found.", appName });
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
});

router.post("/toggle-list", async (req, res) => {
  const { clientID, appName, listType } = req.body;

  // Validate input
  if (
    !clientID ||
    !appName ||
    !listType ||
    !["whitelist", "blocklist"].includes(listType)
  ) {
    return res
      .status(400)
      .send({
        message:
          "Invalid input. Provide clientID, appName, and listType (whitelist/blocklist).",
      });
  }

  const client = await Client.findById(clientID);
  if (!client) {
    return res.status(404).send({ message: "Client not found.", clientID });
  }

  const clientInfo = clientMap.get(clientID);
  const io = getIO();

  if (clientInfo) {
    const socketId = clientInfo.socketId;

    // Find the application
    let app = client.applications.find((app) => app.appName === appName);
    if (!app) {
      return res
        .status(404)
        .send({ message: "Application not found.", appName });
    }

    // Get the previous and current rules
    const prevListType = app.active_list;
    const prevRules = app[prevListType] || [];
    const currentRules = app[listType];

    // Toggle the list type and update the status of rules
    app.active_list = listType;

    if (prevListType) {
      prevRules.forEach((rule) => (rule.status = "inactive"));
    }
    currentRules.forEach((rule) => (rule.status = "active"));

    await client.save();

    console.log(`Switching to ${listType} for client ${clientID}.`);

    // Emit the toggle action with the list to the client via WebSocket
    io.to(socketId).emit("toggle_list", {
      listType,
      appName,
      prevRules,
      currentRules,
    });

    res.send({
      message: `${listType} activated and sent to client.`,
      clientID,
      appName,
      listType,
    });
  } else {
    res.status(404).send({ message: "Client not found.", clientID });
  }
});



router.post("/add-rules" ,async (req , res ) => {
    try {
        const {clientID,rules} = req.body;
        const client = await Client.findById (clientID);
        if (!client) {
            return res.status(404).send({message: "Client not found", clientID})
        }
       
        const commands =[]
        console.log("Adding rules", rules)
        for (const rule of rules) {
            const command = await generateNetshCommand("add",rule);
            commands.push(command)
        }
        res.send({message: "Rules added successfully", commands})
        
    } catch (error) {
        return res.status(500).send({message: "Internal Server Error" , error })
    }


})

export default router;
