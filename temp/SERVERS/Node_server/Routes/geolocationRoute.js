import { Router } from "express";
import axios from "axios";
import { getIO } from "../socket.js";
const router = Router();

router.post("/", (req, res) => {
	const { ip } = req.body;
	try {
		const io = getIO();
		io.emit("block_ip_from_geolocation", {
			message: "Generated request to block country based traffic",
		});
		return res.json({ message: "Successfully blocked the country" });
	} catch (error) {
		return res.json({ message: "Error" });
	}
});

export default router;
