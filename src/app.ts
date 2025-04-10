import RedisStore from "connect-redis";
import cors from "cors";
import express, { Request, Response } from "express";
import rateLimit from "express-rate-limit";
import session from "express-session";
import morgan from "morgan";
import passport from "passport";
import { envVariables } from "./env";
import initialize from "./passport.config";
import redis from "./redis";
import authRoute from "./routes/auth";
import accountRoute from "./routes/account";
import taskRoute from "./routes/task";
import thirdPartyRoute from "./routes/thirdParty";
import userRoute from "./routes/user";
import phaseRoute from "./routes/phase";
import projectRoute from "./routes/project";
import activityHistoryRoute from "./routes/activityHistory";
import vulnRoute from "./routes/vulnerability";
import threatRoute from "./routes/threat";
import artifactRoute from "./routes/artifact";
import ticketRoute from "./routes/ticket";
import permissionRoute from "./routes/permission";
import cweRoute from "./routes/cwe";
import webhookRoute from "./routes/webhook";
import workflowRoute from "./routes/workflow";
import scannerRoute from "./routes/scanner";
import changeHistoryRoute from "./routes/changeHistory";
envVariables.parse(process.env);
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://client-dashboard.up.railway.app",
    ],
    credentials: true,
  })
);
app.use(morgan("dev"));
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 150, // limit each IP to 150 requests per windowMs
});
app.use(limiter);
app.get("/", (req: Request, res: Response) => {
  res.send("server-dashboard API. Start using with /{resource}");
});
const redisStore = new RedisStore({
  client: redis,
});
app.use(
  session({
    store: redisStore,
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
initialize(passport);
app.use(passport.initialize());
app.use(passport.session());
app.use("/auth", authRoute);
app.use("/account", accountRoute);
app.use("/task", taskRoute);
app.use("/thirdParty", thirdPartyRoute);
app.use("/user", userRoute);
app.use("/phase", phaseRoute);
app.use("/project", projectRoute);
app.use("/activity", activityHistoryRoute);
app.use("/vuln", vulnRoute);
app.use("/threat", threatRoute);
app.use("/artifact", artifactRoute);
app.use("/ticket", ticketRoute);
app.use("/permission", permissionRoute);
app.use("/cwe", cweRoute);
app.use("/webhook", webhookRoute);
app.use("/workflow", workflowRoute);
app.use("/scanner", scannerRoute);
app.use("/history", changeHistoryRoute);
export default app;
