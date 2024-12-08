import User from "../Schemas/userSchema.js";
import jwt from "jsonwebtoken";
import { getIO } from "../socket.js";
// import {comparePassword} from '../Schemas/userSchema.js'

// Helper to create JWT
const createToken = (user) => {
	return jwt.sign(
		{ id: user._id, role: user.role, name: user.name },
		"CSS", // Secret key
		{ expiresIn: "7d" } // Token expiration
	);
};

// Register a new user
export const signup = async (req, res) => {
	try {
		const { name, email, password, role } = req.body;

		const existingUser = await User.findOne({ email });
		if (existingUser) {
			return res.status(400).json({ error: "Email already registered" });
		}

		const user = new User({ name, email, password, role });
		await user.save();

		const token = createToken(user);

		const io = getIO();
		const connectedClients = Array.from(io.sockets.sockets.keys());
		console.log(connectedClients);

		res.status(201).json({
			message: "User registered successfully",
			token,
			user: {
				id: user._id,
				user_name: user.name,
				user_email: user.email,
				user_role: user.role,
			},
		});
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

// Login a user
export const login = async (req, res) => {
	try {
		const { email, password } = req.body;

		const user = await User.findOne({ email });
		if (!user) {
			return res.status(400).json({ error: "Invalid email or password" });
		}

		const isMatch = await user.comparePassword(password);
		if (!isMatch) {
			return res.status(400).json({ error: "Invalid email or password" });
		}

		const token = createToken(user);
		const io = getIO();
		const connectedClients = Array.from(io.sockets.sockets.keys());
		console.log(connectedClients);

		res.status(200).json({
			message: "Login successful",
			token,
			name: user.name,
			email: user.email,
			role: user.role,
		});
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};
