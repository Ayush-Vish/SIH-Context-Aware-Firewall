import express, { json } from "express"; // Importing Express framework
import { createServer } from "http"; // Importing HTTP module
import { Server } from "socket.io"; // Importing Socket.IO
import { connect } from "mongoose";
import { createClientByMAC, findClientByMAC } from "./db/client.js";
import { upsertStaticData } from "./db/clientData.js";
import { createAdminByEmail, findAdminByEmail } from "./db/admin.js";
import geolocationRoute from "./Routes/geolocationRoute.js";
import rulesRoute from "./Routes/rulesRoute.js";
import authRoute from "./Routes/authRoute.js";
import { initIO } from "./socket.js";
import cors from "cors";

const app = express(); // Creating an instance of Express
const server = createServer(app); // Creating an HTTP server using Express
const io = initIO(server);
// const io = new Server(server); // Creating a Socket.IO server
const MONGO_URI =
	"mongodb+srv://palashchitnavis:palash1234@css.cyoff.mongodb.net/?retryWrites=true&w=majority&appName=CSS";

app.use(json());
app.use(cors());
app.use("/auth", authRoute);

// Map to store clientId -> { socketId, adminId }
export const clientMap = new Map();

io.on("connection", async (socket) => {
	console.log("Client connection Request:", socket.id);
	const adminEmail = socket.handshake.auth.adminEmail;
	try {
		const adminUser = await findAdminByEmail(adminEmail);
		if (!adminUser) {
			socket.emit("message", {
				message: "Admin Email is invalid.",
				socketID: socket.id,
			});
			socket.disconnect();
			console.log("Client disconnected ", socket.id);
		} else {
			console.log("Client connected to Admin ", adminEmail);
			socket.emit("message", {
				message: "Send initial details",
				sendMACDetails: true,
				adminID: adminUser.adminID,
				socketID: socket.id,
			});
		}
	} catch (error) {
		console.log(error);
	}
	// Listen for MAC addresses sent from the Flask client
	socket.on("mac-address", async (data) => {
		console.log("Received MAC addresses from client:", data.mac_address);
		try {
			const client = await findClientByMAC(data.mac_address);
			if (client) {
				console.log("Client found");
				socket.emit("message", {
					message: "Welcome back!",
					clientID: client.clientID,
					socketID: socket.id,
					adminID: data.adminID,
					sendStaticDetails: true,
				});
				clientMap.set(client.clientID, {
					socketId: socket.id,
					adminID: data.adminID,
				});
			} else {
				const newClient = await createClientByMAC(
					data.mac_address,
					data.adminID
				);
				console.log("Client created");
				socket.emit("message", {
					message: "Welcome new user!",
					clientID: newClient.clientID,
					adminID: data.adminID,
					socketID: socket.id,
					sendStaticDetails: true,
				});
				clientMap.set(newClient.clientID, {
					socketId: socket.id,
					adminID: data.adminID,
				});
			}
		} catch (error) {
			console.error("Error while finding user by MAC:", error);
		}
	});

	socket.on("static-data", async (static_data) => {
		try {
			console.log("Received Static Data from client:", static_data);
			const result = await upsertStaticData(
				static_data.clientID,
				static_data.static_data
			);
			console.log("Static Data Upserted!", result);
			if (result) {
				socket.emit("message", {
					message: "Static Data Upserted!",
					clientID: static_data.clientID,
				});
			} else {
				socket.emit("message", {
					message: "Error upserting Static data",
					clientID: static_data.clientID,
				});
			}
		} catch (error) {
			console.error("Error while finding user by user_id:", error);
		}
	});
	socket.on("v2_response", async(data) => {
		console.log("Received v2 response from client:", data);
		
	})
	socket.on("show_rules", async(data )=>{
		/**
		 * TODO : Send the rules to the client with the clientID
		 * use sockets in the frontend as well
		 * pls
		 *
		 */

		const clientID = data.clientID;

		console.log("Request to show rules");
		console.log(data);
	});
	/**
	 * TODO: Send the alert to the client with the clientID
	 */
	socket.on("process_terminated", async (data) => {
		console.log("Process terminated", data);
	});
	socket.on("agent_error", async (data) => {
		console.log("Agent Error:", data);
	});
	// Handle client disconnect
	socket.on("disconnect", () => {
		console.log("Client disconnected:", socket.id);
	});
});

app.get("/", (req, res) => {
	res.send("Central Admin Dashboard is running on port 3000");
});

app.post("/admin", async (req, res) => {
	const { email, password } = req.body;
	const admin = await createAdminByEmail(email, password);
	if (admin) {
		res.send({ message: "Admin created successfully", admin: admin });
	} else {
		res.send({ message: "error creating admin" });
	}
});
app.post("/add-app-rules", async (req, res) => {
	const { clientID, rule } = req.body;
	const clientInfo = clientMap.get(clientID);
	console.log(clientID, rule);
	if (clientInfo) {
		const socketId = clientInfo.socketId;
		console.log(socketId);
		io.to(socketId).emit("new_app_rule", { rule });
		res.send({ message: "Rule added and sent to client", clientID, rule });
	} else {
		res.status(404).send({ message: "Client not found", clientID });
	}
});

app.use("/geolocation", geolocationRoute);
app.use("/rules", rulesRoute);

// Connect to MongoDB first
connect(MONGO_URI, {})
	.then(() => {
		console.log("Connected to MongoDB");

		// Start the server once the connection to MongoDB is successful
		const PORT = 3000;
		server.listen(PORT, () => {
			console.log(`Server is running on http://localhost:${PORT}`);
		});
	})
	.catch((err) => {
		console.log("Error connecting to MongoDB:", err);
		process.exit(1); // Exit the process if MongoDB connection fails
	});

export default io;
