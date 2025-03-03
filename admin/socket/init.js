import { Server } from "socket.io";

let socket = null;
let nextNamespace = null;
let flaskNamespace = null;

/**
 * Initializes the Socket.IO server and sets up namespaces for Next.js and Flask.
 * @param {http.Server} server - The HTTP server to attach Socket.IO to.
 * @returns {Server} - The initialized Socket.IO server instance.
 */
export const initSocket = (server) => {
    if (!server) {
        throw new Error("Server instance is required to initialize socket.");
    }

    if (socket) {
        console.log("Socket.IO is already initialized.");
        return socket;
    }

    socket = new Server(server);
    console.log("Socket.IO initialized successfully.");

    // Setting up the Next.js namespace
    nextNamespace = socket.of("/nextjs");
    nextNamespace.on("connection", (socket) => {
        
        console.log("Next.js connected:", socket.id);

        socket.on("message", (msg) => {
            console.log("Message from Next.js:", msg);
        });

        socket.on("disconnect", () => {
            console.log("Next.js disconnected:", socket.id);
        });
    });

    // Setting up the Flask namespace
    flaskNamespace = socket.of("/flask");
    flaskNamespace.on("connection", (socket) => {
        console.log("Flask connected:", socket.id);

        socket.on("message", (msg) => {
            console.log("Message from Flask:", msg);
        });

        socket.on("disconnect", () => {
            console.log("Flask disconnected:", socket.id);
        });
    });

    return socket;
};

/**
 * Retrieves the Socket.IO server instance.
 * @returns {Server} - The Socket.IO server instance, or a mock object if not initialized.
 */
export const getSocket = () => {
    if (!socket) {
        console.warn("Socket.IO is not initialized yet.");
        return {
            on: () => console.warn("Socket.IO is not ready to handle events."),
            emit: () => console.warn("Socket.IO is not ready to emit events."),
        };
    }

    return socket;
};

/**
 * Retrieves the Next.js namespace instance.
 * @returns {Namespace} - The Next.js namespace instance, or null if not initialized.
 */
export const getNextNamespace = () => {
    if (!nextNamespace) {
        console.warn("Next.js namespace is not initialized yet.");
        return null;
    }
    return nextNamespace;
};

/**
 * Retrieves the Flask namespace instance.
 * @returns {Namespace} - The Flask namespace instance, or null if not initialized.
 */
export const getFlaskNamespace = () => {
    if (!flaskNamespace) {
        console.warn("Flask namespace is not initialized yet.");
        return null;
    }
    return flaskNamespace;
};
