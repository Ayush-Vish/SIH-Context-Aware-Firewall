import express from "express"
import {createServer} from "http"
import { connect } from "mongoose"
import { initSocket } from "./socket/init.js"
import { findAdminByEmail, findAdminByID } from "./db/admin.js"
import { message } from "./socket/message.js"
import { createClientByMAC, findClientByMAC } from "./db/client.js"
import { upsertStaticData } from "./db/clientData.js"
const app = express()
const server = createServer(app)
const socket = initSocket(server)
const MONGO_URL = "mongodb+srv://palashchitnavis:palash1234@css.cyoff.mongodb.net/?retryWrites=true&w=majority&appName=CSS";

app.use(express.json());

// Map clientID -> {socketID , adminID}
export const clientMap = new Map();

// socket connect
socket.on("connect", async (socket) => {
    console.log("connection request : ",socket.id);
    const adminEmail = socket.handshake.auth.adminEmail;
    try{
        const admin = await findAdminByEmail(adminEmail)
        if(!admin){
            message("admin email invalid",{
                tryAgain: true
            })
            console.log("telling client to try again");
            socket.disconnect(true)
        }else{
            console.log("client connected to admin ",adminEmail);
            message("send mac details",{
                sendMACDetails: true,
                socketID: socket.id,
                adminID: admin.adminID
            })
        }
    }catch(error){
        console.log(error);
        console.log("admin email part error");
    }

    socket.on("mac-address", async (data) => {
        console.log("recieved mac details from client");
        try{
            const client = await findClientByMAC(data.mac)
            if(client){
                console.log("client found");
                message("welcome back!",{
                    clientID: client.clientID,
					socketID: socket.id,
					adminID: data.identity.adminID,
					sendStaticDetails: true
                })
                clientMap.set(client.clientID , {
                    socketID: socket.id,
                    adminID: data.identity.adminID
                })
            }else{
                const newClient = await createClientByMAC(data.mac,data.identity.adminID)
                console.log("client created");
                message("welcome new user!",{
                    clientID: newClient.clientID,
					adminID: data.identity.adminID,
					socketID: socket.id,
					sendStaticDetails: true,
                })
                clientMap.set(newClient.clientID, {
					socketID: socket.id,
					adminID: data.identity.adminID,
				});
                const admin = await findAdminByID(data.identity.adminID)
                admin.clientID.push(newClient.clientID);
                await admin.save()
            }
            console.log(clientMap);
            
        }catch(error){
            console.log(error);
            console.log("error in mac details part");
        }
    })

    socket.on("static-details", async (data) => {
        try{
            console.log("recieved static data from client.");
            const result = await upsertStaticData(data.identity.clientID,data.static)
            if(result){
                message("static data upserted",{})
                console.log("static data upserted");
            }else{
                message("error upserting",{sendStaticDetails: true})
                console.log("error upserting , asking again");
            }
        }catch(error){
            console.log(error);
            console.log("error in static data part");
        }
    })
})

// Function to send the "resend static data" message every 10 minutes
const resendStaticDataMessage = () => {
    setInterval(() => {
        clientMap.forEach(({ socketID, adminID }) => {
            message("resend static data", {sendStaticDetails: true})
            console.log(`Sent request to client ${socketID} to resend static data`);
        });
    }, 10 * 60 * 1000);
}

resendStaticDataMessage()

app.get("/",(req,res) => {
    res.send("dashboard running on port 3000")
})

app.post("/static-data",(req,res)=>{
    message("resend static data",{sendStaticDetails: true})
    res.end()
})

connect(MONGO_URL,{})
    .then(() => {
        console.log("connected to mongo db");
        const PORT = 3000
        server.listen(PORT,() => {
            console.log("server is running on localhost 3000");
        })  
    })
    .catch((error) => {
        console.log(error);
        console.log("error in mongo db connection part");
        process.exit(1)
    })
