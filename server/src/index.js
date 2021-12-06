require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcryptjs");
const {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken,
} = require("./tokens");

const { fakeDB } = require("./fakeDB.js");
const { isAuth } = require("./isAuth");

//1.Register a user
//2.Login a user
//3.Logout a user
//4.protected route
//5.get a new access token with a refresh token

const server = express();

//use express middleware for easier cookie handling

server.use(cookieParser());

server.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

//needed to be able to read body data
server.use(express.json()); //to support JSON-encoded bodies
server.use(express.urlencoded({ extended: true })); //support url encoded body

//Register a user
server.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    //1.Check if user exist
    const user = fakeDB.find((user) => user.email === email);
    //review this line####
    //if (user) throw new Error("User already exist");
    //if (user) throw new Error({ message: "User already exist" });
    if (user) {
      return res.status(400).json({ message: "User already exist" });
    }
    //2.If not user exist, hash the password
    const hashedPassword = await hash(password, 10);
    //3.Insert the user in "database"
    fakeDB.push({
      id: fakeDB.length,
      email,
      password: hashedPassword,
    });
    res.send({ messasge: "User Created" });
    // console.log(hashedPassword);
    console.log(fakeDB);
  } catch (err) {
    res.send({
      error: `${err.messasge}`,
    });
  }
});
//LogIn a User
server.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    //1.Find users in database. If not exist used error
    const user = fakeDB.find((user) => user.email === email);
    if (!user) {
      return res.status(400).json({ message: "User doesnot exist" });
    }
    //2. compare crypted password and see if checks out. Send error if not
    const valid = await compare(password, user.password);
    if (!valid) throw new Error("Password not corrected");
    //5.Create Refersh and Accesstoken
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    //4. Put refreshtoken in database
    user.refreshtoken = refreshtoken;
    console.log(fakeDB);
    //5.send token, Refreshtoken as a cookie and accesstoken as a regular response
    sendRefreshToken(res, refreshtoken);
    sendAccessToken(res, req, accesstoken);
  } catch (err) {
    res.send({
      error: `${err.message}`,
    });
  }
});

//Logout a user
server.post("/logout", (_req, res) => {
  res.clearCookie("refreshtoken", { path: "/refresh_token" });
  return res.send({
    message: "Logged out",
  });
});
//4.Protected route
server.post("/protected", async (req, res) => {
  try {
    const userId = isAuth(req);
    if (userId !== null) {
      res.send({
        data: "This is protected data",
      });
    }
  } catch (err) {
    res.send({
      error: `${err.message}`,
    });
  }
});

//Get a new accesstoken with a refreshtoken
server.post("/refresh_token", (req, res) => {
  const token = req.cookies.refreshtoken;
  //if we dont have a token in our request
  if (!token) return res.send({ accesstoken: "" });
  //we have a token, let's verify it
  let payload = null;
  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    return res.send({ accesstoken: "" });
  }
  //Token is valid, check if user exist
  const user = fakeDB.find((user) => user.id === payload.userId);
  if (!user) return res.send({ accesstoken: "" });
  //user exist, check if refreshtoken exist on user
  if (user.refreshtoken !== token) {
    return res.send({ accesstoken: "" });
  }
  //token exist, create new refresh and accesstoken
  const accesstoken = createAccessToken(user.id);
  const refreshtoken = createRefreshToken(user.id);
  user.refreshtoken = refreshtoken;
  //All good to go, send new refreshtoken and accesstoken
  sendRefreshToken(res, refreshtoken);
  return res.send({ accesstoken });
});

server.listen(process.env.PORT, () =>
  console.log(`Server listening on port ${process.env.PORT}`)
);
