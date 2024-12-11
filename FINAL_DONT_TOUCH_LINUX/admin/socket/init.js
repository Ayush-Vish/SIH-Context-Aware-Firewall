let socket = null;
import { Server } from "socket.io";

export const initSocket = (server) => {
    socket = new Server(server)
    console.log("socket initialized");
    return socket
}

export const getSocket = () => {
    if(!socket){
        console.log("socket is not initialized");
        return {
			on: () => console.log("socket is not ready to use."),
			emit: () => console.log("socket is not ready to emit events."),
		};
    }
    return socket
}