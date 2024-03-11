import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import {rsaEncrypt, symEncrypt, createRandomSymmetricKey, exportSymKey, importPubKey} from "../crypto";
import {Node} from "../registry/registry";

// Defines the structure for messages sent by users.
export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

// Initializes the user service with necessary configurations and routes.
export async function user(userId: number) {
  const _user = express();
  // Middleware to parse JSON bodies.
  _user.use(express.json());
  // Middleware to parse URL-encoded bodies.
  _user.use(bodyParser.json());

  // Variables to track the state of the last messages and circuit used.
  var lastReceivedMessage: string | null = null;
  var lastSentMessage: string | null = null;
  var lastCircuit : Node[] = [];

  // Route to confirm the service is operational.
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Routes to retrieve the last received message, last sent message, and the last circuit used.
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit.map((node) => node.nodeId) });
  });

  // Route to send an encrypted message through the network.
  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;
    // Fetches the list of nodes from the registry.
    const nodes = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`)
        .then((res) => res.json())
        .then((body: any) => body.nodes);
    // Randomly selects a circuit of nodes.
    let circuit: Node[] = [];
    for (let i = nodes.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [nodes[i], nodes[j]] = [nodes[j], nodes[i]];
    }
    circuit = nodes.slice(0, 3);

    lastSentMessage = message;
    let messageToSend = lastSentMessage;
    // Validates the message content.
    if (messageToSend === null || messageToSend === undefined || messageToSend === "") {
      res.status(400).json({ error: 'Request body must contain a message property' });
      return;
    }
    // Encrypts the message for each node in the circuit.
    for (let i = circuit.length - 1; i >= 0; i--) {
      const node = circuit[i];
      const symKey = await createRandomSymmetricKey();
      const destination = i == circuit.length - 1 ?
          `${BASE_USER_PORT + destinationUserId}`.padStart(10, '0') :
          `${BASE_ONION_ROUTER_PORT + circuit[i + 1].nodeId}`.padStart(10, '0');
      const messageToEncrypt = `${destination + messageToSend}`;
      const encryptedMessage = await symEncrypt(symKey, messageToEncrypt);
      const encryptedSymKey = await rsaEncrypt(await exportSymKey(symKey), node.pubKey);
      messageToSend = encryptedSymKey + encryptedMessage;
    }
    // Sends the encrypted message to the entry node.
    const entryNode = circuit[0];
    lastCircuit = circuit;
    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + entryNode.nodeId}/message`, {
      method: "POST",
      body: JSON.stringify({ message: messageToSend }),
      headers: { "Content-Type": "application/json" },
    });
    lastSentMessage = message;
    res.send("success");
  });

  // Route to receive messages sent to the user.
  _user.post("/message", (req, res) => {
    if (req.body.message) {
      lastReceivedMessage = req.body.message;
      res.status(200).send("success");
    } else {
      res.status(400).json({ error: 'Request body must contain a message property' });
    }
  });

  // Starts the server for this user node.
  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}
