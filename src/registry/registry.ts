import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = {
  nodeId: number;
  pubKey: string
};

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

// In-memory storage for registered nodes
const nodesRegistry: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // TODO implement the status route
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // Route for nodes to register themselves
  _registry.post("/registerNode", (req: Request, res: Response) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;

    // Check if the node is already registered
    const index = nodesRegistry.findIndex(node => node.nodeId === nodeId);

    if (index !== -1) {
      // Node already exists, update its public key
      nodesRegistry[index].pubKey = pubKey;
      res.json({ message: "Node updated successfully." });
    } else {
      // Register new node
      nodesRegistry.push({ nodeId, pubKey });
      res.json({ message: "Node registered successfully." });
    }
  });

  _registry.get("/getNodeRegistry", (req, res) => {
    res.json({ nodes: nodesRegistry });
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}