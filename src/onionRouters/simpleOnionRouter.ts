import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, importPrvKey, rsaDecrypt, symDecrypt } from "../crypto";

// Initializes an onion router with a given nodeId.
export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  // Setup middleware to parse JSON request bodies.
  onionRouter.use(express.json());

  // State variables to keep track of message handling.
  var lastReceivedEncryptedMessage: string | null = null;
  var lastReceivedDecryptedMessage: string | null = null;
  var lastMessageDestination: number | null = null;

  // Generate RSA key pair for the router and export keys to Base64.
  const { publicKey, privateKey } = await generateRsaKeyPair();
  const privateKeyBase64 = await exportPrvKey(privateKey);
  const publicKeyBase64 = await exportPubKey(publicKey);

  // Route to check the router's operational status.
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // Routes to retrieve the last encrypted/decrypted message and its intended destination.
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  // Route to expose the router's private key (use with caution, primarily for debugging).
  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privateKeyBase64 });
  });

  // Registers the router with the node registry.
  const response = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      nodeId,
      pubKey: publicKeyBase64,
    }),
  });

  // Handle registration failure.
  if (!response.ok) {
    throw new Error(`Failed to register node: ${response.statusText}`);
  }

  // Route to handle encrypted messages sent to this router.
  onionRouter.post("/message", async (req, res) => {
    const layer = req.body.message; // The encrypted message layer received.
    // Separate the symmetric key and the encrypted message parts.
    const encryptedSymKey = layer.slice(0, 344);
    // Decrypt the symmetric key using the router's private key.
    const symKey = privateKeyBase64 ? await rsaDecrypt(encryptedSymKey, await importPrvKey(privateKeyBase64)) : null;
    const encryptedMessage = layer.slice(344);
    // Decrypt the message using the symmetric key.
    const message = symKey ? await symDecrypt(symKey, encryptedMessage) : null;
    // Update state with the latest message handling results.
    lastReceivedEncryptedMessage = layer;
    lastReceivedDecryptedMessage = message ? message.slice(10) : null;
    lastMessageDestination = message ? parseInt(message.slice(0, 10), 10) : null;
    // Forward the decrypted message to its next destination.
    await fetch(`http://localhost:${lastMessageDestination}/message`, {
      method: "POST",
      body: JSON.stringify({ message: lastReceivedDecryptedMessage }),
      headers: { "Content-Type": "application/json" },
    });
    res.send("success");
  });

  // Start listening for requests on the router's designated port.
  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}
