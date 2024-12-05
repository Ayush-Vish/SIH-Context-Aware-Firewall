const express = require("express"); // Importing Express framework
const http = require("http"); // Importing HTTP module
const { Server } = require("socket.io"); // Importing Socket.IO

const app = express(); // Creating an instance of Express
const server = http.createServer(app); // Creating an HTTP server using Express
const io = new Server(server); // Creating a Socket.IO server

app.use(express.json());

io.on("connection", (socket) => {
	console.log("Client connected:", socket.id);

	// Listen for MAC addresses sent from the Flask client
	socket.on("mac-address", (mac_addresses) => {
		console.log("Received MAC addresses from client:", mac_addresses);
	});

	// Handle client disconnect
	socket.on("disconnect", () => {
		console.log("Client disconnected:", socket.id);
	});
});

app.get("/", (req, res) => {
	res.send("Central Admin Dashboard is running on port 3000");
});

app.post("/get-ip-from-domain", async (req, res) => {
	const { domain } = req.body;
	io.emit("get_ip_from_domain", domain);
	console.log("Emitted domain to flask : ", domain);
	return res.status(200).json({ message: "Response ips from Flask" });
});

io.on("get_ip_from_domain_response", (ip_array) => {
	console.log("Response from Flask:", ip_array);
});

const PORT = 3000;
server.listen(PORT, () => {
	console.log(`Server is running on http://localhost:${PORT}`);
});
