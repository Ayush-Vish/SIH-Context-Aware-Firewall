import { Router } from "express";
import axios from "axios";
import { getIO } from "../socket.js";
import { clientMap } from "../index.js";
const router = Router();


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



export default router