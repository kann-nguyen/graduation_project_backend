import express from "express";
import {
  getAll,
  get,
  create,
  update,
  remove
} from "../controllers/mitigation.controller";

const mitigationRoute = express.Router();

// 1. Get all mitigations
mitigationRoute.get("/", getAll);

// 2. Get mitigations for a specific threat
mitigationRoute.get("/threat/:threatId", get);

// 3. Create a new mitigation and add it to a threat
mitigationRoute.post("/", create);

// 4. Update an existing mitigation
mitigationRoute.patch("/:id", update);

// 5. Remove a mitigation from a threat and delete it from database
mitigationRoute.delete("/:id/threat/:threatId", remove);

export default mitigationRoute;