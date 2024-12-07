import { Router } from "express";
import axios from "axios";
import { getIO } from "../socket.js";
import { clientMap } from "../index.js";
const router = Router();
/**
 * TODO : Save the rules in the DB as well for all controllers.
 *  
 */

router.post("/add-app-rules" , async (req,res)=>{
    console.log("Request to add rule", req.body);
	const { clientID, rule } = req.body;
    const clientInfo = clientMap.get(clientID);
	console.log(
		clientID,rule
	)
    const io = getIO()
    if (clientInfo) {
        const socketId = clientInfo.socketId;
	  console.log(socketId)
        io.to(socketId).emit("new_app_rule", { rule });
        
        res.send({ message: "Rule added and sent to client", clientID, rule });
    } else {
        console.log("Client not found", clientID);
        res.status(404).send({ message: "Client not found", clientID });
    }
})

router.post("/block-domain" , async(req , res )=>  { 
    const { clientID, rule  } = req.body;
    const clientInfo = clientMap.get(clientID);
    const io = getIO()
    if (clientInfo) {
        const socketId = clientInfo.socketId;
        console.log(socketId)
        console.log("Sending domain block request to client", rule) 
        io.to(socketId).emit("block_domain", { rule });
        res.send({ message: "Domain blocked and sent to client", clientID, rule });
    } else {
        res.status(404).send({ message: "Client not found", clientID });
    }
    
})

router.post("/block-port" , async(req , res )=>  {
    const { clientID, rule  } = req.body;
    const clientInfo = clientMap.get(clientID);
    const io = getIO()
    if (clientInfo) {
        const socketId = clientInfo.socketId;
        console.log(socketId)
        console.log("Sending port block request to client", rule) 
        io.to(socketId).emit("block_port", { rule });
        res.send({ message: "Port blocked and sent to client", clientID, rule });
    } else {
        res.status(404).send({ message: "Client not found", clientID });
    }
})

router.get("/get-rules/:clientID", async (req, res) => {

    const { clientID } = req.params;
    const clientInfo = clientMap.get(clientID);
    const io = getIO()
    if (clientInfo) {
        const socketId = clientInfo.socketId;
        console.log(socketId)
        console.log("Requesting rules from client", clientID) 
        io.to(socketId).emit("get_rules", { clientID });
        res.send({ message: "Request sent to client", clientID });
    } else {
        res.status(404).send({ message: "Client not found", clientID });
    }

    
});


export default router