const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const {
    generateRegistrationOptions,
    verifyRegistrationResponse
} = require("@simplewebauthn/server"); // ✅ Import WebAuthn functions

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());

let userDB = {}; // Store user data

app.post("/register", async (req, res) => {
    const { username } = req.body;
    const options = await generateRegistrationOptions({
        rpName: "Fair Elect",
        rpID: "localhost", // ✅ Required for WebAuthn
        userID: username,
        userName: username,
    });

    userDB[username] = { challenge: options.challenge };
    res.json(options);
});

app.post("/verify-registration", async (req, res) => {
    const { username, attestationResponse } = req.body;
    const expectedChallenge = userDB[username]?.challenge;

    try {
        const verification = await verifyRegistrationResponse({
            response: attestationResponse,
            expectedChallenge,
            expectedRPID: "localhost",
            expectedOrigin: "http://localhost:3000",
        });

        if (verification.verified) {
            userDB[username].credential = verification.registrationInfo;
            res.json({ success: true, message: "Fingerprint registered!" });
        } else {
            res.status(400).json({ success: false, message: "Verification failed" });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.listen(3000, () => {
    console.log("🚀 Server running on http://localhost:3000");
});
