import request from "supertest";
import app from "../src/app";
import { describe, it } from "vitest";

describe("GET /", () => {
  it("should return 200 OK", () => request(app).get("/").expect(200));
});
