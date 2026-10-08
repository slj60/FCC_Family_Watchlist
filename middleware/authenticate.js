import { verifyToken } from "../utils/jwt.js"
import { isBlacklisted } from "../utils/token-blacklist.js"

export function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ "error": "No token provided." })
    }
    const token = authHeader.split(" ")[1];

    if(isBlacklisted(token)) {
        return res.status(401).json({ "error": "Invalid or expired token." })
    }

    const verification = verifyToken(token);

    if (!verification) {
        return res.status(401).json({ "error": "Invalid or expired token." })
    }

    req.user = verification;

    next();
}
