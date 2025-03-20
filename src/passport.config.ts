import bcrypt from "bcrypt";
import { PassportStatic } from "passport";
import Github from "passport-github2";
import Gitlab from "passport-gitlab2";
import Local from "passport-local";
import { AccountModel, UserModel } from "./models/models";
import { Request } from "express";
const LocalStrategy = Local.Strategy;
const GithubStrategy = Github.Strategy;
const GitlabStrategy = Gitlab.Strategy;
type GitlabProfile = Github.Profile; // No TypeScript support for passport-gitlab2
async function authenticateUserLocal(
  username: string,
  password: string,
  done: (error: any, user?: any) => void
) {
  try {
    const account = await AccountModel.findOne({ username });
    if (!account) {
      return done(null, false);
    }
    if (await bcrypt.compare(password, account.password)) {
      return done(null, account);
    }
    return done(null, false);
  } catch (e) {
    return done(e);
  }
}
async function authenticateUserGithub(
  req: Request,
  accessToken: string,
  refreshToken: string,
  profile: Github.Profile,
  done: (error: any, user?: any) => void
) {
  // User is already login with local instance. Link the Github account to the local account
  if (req.user) {
    await Promise.all([
      AccountModel.findByIdAndUpdate(req.user._id, {
        $push: {
          thirdParty: {
            name: "Github",
            username: profile.username,
            accessToken,
            refreshToken,
          },
        },
      }),
      AccountModel.findOneAndDelete({ username: `Github_${profile.username}` }),
    ]);
    return done(null, req.user);
  } else {
    try {
      // Check if there is an account that has already linked to this Github account
      const linkedAccount = await AccountModel.findOne({
        "thirdParty.username": profile.username,
        "thirdParty.name": "Github",
      });
      if (linkedAccount) {
        await updateToken(linkedAccount, accessToken, refreshToken, "Github");
        return done(null, linkedAccount);
      }
      const account = await AccountModel.findOne({
        username: `Github_${profile.username}`,
      });
      // First time login
      if (!account) {
        const newAccount = await registeringGithubFirstTime(
          profile,
          accessToken,
          refreshToken
        );
        return done(null, newAccount);
      }
      return done(null, account);
    } catch (e) {
      return done(e);
    }
  }
}
async function updateToken(
  linkedAccount: any,
  accessToken: string,
  refreshToken: string,
  vendor: "Github" | "Gitlab"
) {
  const filter = {
    _id: linkedAccount._id,
    "thirdParty.name": vendor,
  };
  const update = {
    $set: {
      "thirdParty.$.accessToken": accessToken,
      "thirdParty.$.refreshToken": refreshToken,
    },
  };
  await AccountModel.findOneAndUpdate(filter, update, {
    new: true,
  });
}

async function registeringGithubFirstTime(
  profile: Github.Profile,
  accessToken: string,
  refreshToken: string
) {
  const password = await bcrypt.hash(`Github_${profile.username}`, 10);
  const newAccount = await AccountModel.create({
    username: `Github_${profile.username}`,
    password,
    email: profile.emails ? profile.emails[0].value : "",
    thirdParty: [
      {
        name: "Github",
        username: profile.username,
        accessToken,
        refreshToken,
      },
    ],
  });
  await UserModel.create({
    name: profile.displayName,
    account: newAccount._id,
  });
  return newAccount;
}

async function authenticateUserGitlab(
  req: Request,
  accessToken: string,
  refreshToken: string,
  profile: GitlabProfile,
  done: (error: any, user?: any) => void
) {
  if (req.user) {
    await Promise.all([
      AccountModel.findByIdAndUpdate(req.user._id, {
        $push: {
          thirdParty: {
            name: "Gitlab",
            username: profile.username,
            accessToken,
            refreshToken,
          },
        },
      }),
      AccountModel.findOneAndDelete({ username: `Gitlab_${profile.username}` }),
    ]);

    return done(null, req.user);
  } else {
    try {
      // Check if there is an account that has already linked to this Gitlab account
      const linkedAccount = await AccountModel.findOne({
        "thirdParty.username": profile.username,
        "thirdParty.name": "Gitlab",
      });
      if (linkedAccount) {
        await updateToken(linkedAccount, accessToken, refreshToken, "Gitlab");
        return done(null, linkedAccount);
      }
      const account = await AccountModel.findOne({
        username: `Gitlab_${profile.username}`,
      });
      // First time login
      if (!account) {
        const newAccount = await registeringGitlabFirstTime(
          profile,
          accessToken,
          refreshToken
        );
        return done(null, newAccount);
      }
      return done(null, account);
    } catch (e) {
      return done(e);
    }
  }
}
async function registeringGitlabFirstTime(
  profile: GitlabProfile,
  accessToken: string,
  refreshToken: string
) {
  const password = await bcrypt.hash(`Gitlab${profile.username}`, 10);
  const newAccount = await AccountModel.create({
    username: `Gitlab_${profile.username}`,
    password,
    email: profile.emails ? profile.emails[0].value : "",
    thirdParty: [
      {
        name: "Gitlab",
        username: profile.username,
        accessToken,
        refreshToken,
      },
    ],
  });
  await UserModel.create({
    name: profile.displayName,
    account: newAccount._id,
  });
  return newAccount;
}

function initialize(passport: PassportStatic) {
  useGithubOAuth(passport);
  useGitlabOAuth(passport);
  useLocalAuth(passport);
  passport.serializeUser((account, done) => done(null, account._id));
  passport.deserializeUser(async (id: string, done) => {
    try {
      const results = await AccountModel.findById(id);
      if (results) {
        return done(null, results);
      }
    } catch (error) {
      return done(error);
    }
  });
}

export default initialize;
function useLocalAuth(passport: PassportStatic) {
  passport.use(
    new LocalStrategy({ usernameField: "username" }, authenticateUserLocal)
  );
}

function useGithubOAuth(passport: PassportStatic) {
  passport.use(
    new GithubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: `${process.env.SERVER_URL}/auth/github/callback`,
        passReqToCallback: true,
      },
      authenticateUserGithub
    )
  );
}
function useGitlabOAuth(passport: PassportStatic) {
  passport.use(
    new GitlabStrategy(
      {
        clientID: process.env.GITLAB_CLIENT_ID,
        clientSecret: process.env.GITLAB_CLIENT_SECRET,
        callbackURL: `${process.env.SERVER_URL}/auth/gitlab/callback`,
        passReqToCallback: true,
      },
      authenticateUserGitlab
    )
  );
}
