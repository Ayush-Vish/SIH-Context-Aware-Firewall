let io;
import { Server } from "socket.io";
export const initIO = (server) => {
	io = new Server(server);
	console.log("Socket.IO initialized");
	return io;
};

export const getIO = () => {
	if (!io) {
		console.warn("Socket.IO is not initialized yet.");
		return {
			on: () => console.warn("Socket.IO is not ready to use."),
			emit: () => console.warn("Socket.IO is not ready to emit events."),
		};
	}
	return io;
};
