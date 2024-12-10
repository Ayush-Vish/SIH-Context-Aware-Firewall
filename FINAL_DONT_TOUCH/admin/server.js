import express from "express";
import { createServer } from "http";
import { connect } from "mongoose";
import { initSocket } from "./socket/init.js";
import {
	createAdminByEmail,
	findAdminByEmail,
	findAdminByID,
} from "./db/admin.js";
import { message } from "./socket/message.js";
import { createClientByMAC, findClientByMAC } from "./db/client.js";
import { getStaticData, upsertStaticData } from "./db/clientData.js";
import rulesRoutes from "./Routes/rulesRoute.js";
// import staticInfoRoute from "./Routes/staticInfoRoute.js";
import { parseFirewallRules } from "./utils/command.js";
const app = express();
const server = createServer(app);
const socket = initSocket(server);
const MONGO_URL =
	"mongodb+srv://palashchitnavis:palash1234@css.cyoff.mongodb.net/?retryWrites=true&w=majority&appName=CSS";

app.use(express.json());
// app.use("/static", staticInfoRoute);
// Map clientID -> {socketID , adminID}
export const clientMap = new Map();

// socket connect
socket.on("connect", async (socket) => {
	console.log("connection request : ", socket.id);
	const adminEmail = socket.handshake.auth.adminEmail;
	try {
		const admin = await findAdminByEmail(adminEmail);
		if (!admin) {
			message("admin email invalid", {
				tryAgain: true,
			});
			console.log("telling client to try again");
			socket.disconnect(true);
		} else {
			console.log("client connected to admin ", adminEmail);
			message("send mac details", {
				sendMACDetails: true,
				socketID: socket.id,
				adminID: admin.adminID,
			});
		}
	} catch (error) {
		console.log(error);
		console.log("admin email part error");
	}

	socket.on("mac-address", async (data) => {
		console.log("recieved mac details from client");
		try {
			const client = await findClientByMAC(data.mac);
			if (client) {
				console.log("client found");
				message("welcome back!", {
					clientID: client.clientID,
					socketID: socket.id,
					adminID: data.identity.adminID,
					sendStaticDetails: true,
				});
				clientMap.set(client.clientID, {
					socketID: socket.id,
					adminID: data.identity.adminID,
				});
			} else {
				const newClient = await createClientByMAC(
					data.mac,
					data.identity.adminID
				);
				console.log("client created");
				message("welcome new user!", {
					clientID: newClient.clientID,
					adminID: data.identity.adminID,
					socketID: socket.id,
					sendStaticDetails: true,
				});
				clientMap.set(newClient.clientID, {
					socketID: socket.id,
					adminID: data.identity.adminID,
				});
				const admin = await findAdminByID(data.identity.adminID);
				admin.clientID.push(newClient.clientID);
				await admin.save();
			}
			console.log(clientMap);
		} catch (error) {
			console.log(error);
			console.log("error in mac details part");
		}
	});

	socket.on("static-details", async (data) => {
		try {
			console.log("recieved static data from client.");
			const result = await upsertStaticData(
				data.identity.clientID,
				data.static
			);
			if (result) {
				message("static data upserted", {});
				console.log("static data upserted");
			} else {
				message("error upserting", { sendStaticDetails: true });
				console.log("error upserting , asking again");
			}
		} catch (error) {
			console.log(error);
			console.log("error in static data part");
		}
	});
	socket.on("firewall_alert" ,async(data ) => {
		console.log(data);
		
	})
	socket.on("response" , async (data ) =>{
		if(data.rule_type === "get_rules") {
			console.log(JSON.stringify(data.response[0]));

			// console.log("v2 response from client", parseFirewallRules( JSON.stringify(data.response[0]))[0]);
		}
		
		// console.log("v2 response from client", data);
	})
});

// Function to send the "resend static data" message every 10 minutes
const resendStaticDataMessage = () => {
	setInterval(() => {
		clientMap.forEach(({ socketID, adminID }) => {
			message("resend static data", { sendStaticDetails: true });
			console.log(`Sent request to client ${socketID} to resend static data`);
		});
	}, 10 * 60 * 1000);
};

resendStaticDataMessage();

app.get("/", (req, res) => {
	res.send("dashboard running on port 3000");
});

app.use("/rules" , rulesRoutes);

app.post("/admin/signup", async (req, res) => {
	const { email, password } = req.body;
	const admin = await findAdminByEmail(email);
	if (admin) {
		res.send({
			message: "admin with email already exists",
		});
		return;
	}
	const newAdmin = await createAdminByEmail(email, password);
	res.send({
		message: "new admin created",
		admin: newAdmin,
	});
	return;
});

app.post("/admin/signin", async (req, res) => {
	const { email, password } = req.body;
	const admin = await findAdminByEmail(email);
	if (!admin) {
		res.send({
			message: "admin for given email doesnt exist",
		});
		return;
	} else if (admin.password != password) {
		res.send({
			message: "incorrect password",
		});
		return;
	}
	res.send({
		message: "login successfull",
		admin: admin,
	});
});

app.post("/details/client/", (req, res) => {
	const { clientID } = req.body;
	console.log("Client ID received:", clientID);

	const result = clientMap.get(clientID);
	console.log("Client result from map:", result);

	if (!result) {
		return res.send({
			message: "device is not online",
			error: true,
		});
	}

	console.log("Socket ID for client:", result.socketID);
	try {
		if (result.socketID) {
			socket.to(result.socketID).emit("message", {
				message: "resend static data",
				flags: {
					sendStaticDetails: true,
				},
			});

			res.send({
				message: "Static data resend request sent successfully",
				error: false,
			});
		} else {
			console.log("Error: No socketID found for client");
			res.status(500).send({
				message: "No socketID found for client",
				error: true,
			});
		}
	} catch (error) {
		console.log("Error sending socket message:", error);
		res.status(500).send({
			message: "Error sending socket message",
			error: true,
		});
	}
});

app.post("/details/admin", async (req, res) => {
	const { email } = req.body;
	const admin = await findAdminByEmail(email);
	if (!admin) {
		res.send({
			message: "admin for given email doesnt exist",
		});
		return;
	}
	res.send({
		message: "admin details",
		admin: admin,
	});
});

app.post("/details/clients", async (req, res) => {
	const { clientIDS } = req.body;

	try {
		// Use Promise.all to wait for all async operations to complete
		const staticDataPromises = clientIDS.map(async (clientID) => {
			const data = await getStaticData(clientID);
			return data; // Return the data for Promise.all to resolve
		});

		// Wait for all promises to resolve
		const staticData = await Promise.all(staticDataPromises);

		res.send({
			message: "client static data",
			data: staticData,
		});
	} catch (error) {
		console.log("Error getting static data:", error);
		res.status(500).send({ message: "Error fetching data" });
	}
});

connect(MONGO_URL, {})
	.then(() => {
		console.log("connected to mongo db");
		const PORT = 3000;
		server.listen(PORT, () => {
			console.log("server is running on localhost 3000");
		});
	})
	.catch((error) => {
		console.log(error);
		console.log("error in mongo db connection part");
		process.exit(1);
	});
