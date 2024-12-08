import { getSocket } from "./init.js";

export const message = (message , flags) => {
    const socket = getSocket()
    socket.emit("message",{
        message: message,
        flags: flags
    })
    return
}