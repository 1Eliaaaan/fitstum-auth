import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import { res } from "./responses.mjs";
import { userStore } from "./model.mjs";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,20}$/; // Min 8, Max 20, al menos 1 símbolo, 1 mayúscula, 1 número

export const handler = async (event) => {
  try {
    console.log("EVENT", event);
    const route = event.routeKey;

    switch (route) {
      case "POST /auth/login": {
        let body = JSON.parse(event.body);

        if (!body.email || !emailRegex.test(body.email)) {
          return res("Invalid email format", 400);
        }
        if (!body.password) {
          return res("Password is required", 400);
        }

        const { email, password } = body;

        const user = await userStore.findByEmail(email);
        if (!user) {
          return res("Invalid credentials", 401);
        }

        const isPasswordValid = await bcryptjs.compare(password, user.password);
        if (!isPasswordValid) {
          return res("Invalid credentials", 401);
        }

        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });

        return res(user, 200, {
          "Set-Cookie": `token=${token}; HttpOnly; Max-Age=3600; Path=/`,
        });
      }

      case "POST /auth/register": {
        let body = JSON.parse(event.body);

        if (!body.email || !emailRegex.test(body.email)) {
          return res("Invalid email format", 400);
        }
        if (!body.password || !passwordRegex.test(body.password)) {
          return res(
            "Password must be 8-20 characters long, include at least one uppercase letter, one number, and one symbol",
            400
          );
        }
        if (!body.username) {
          return res("Username is required", 400);
        }

        const { username, email, password } = body;

        const existingUser = await userStore.findByEmail(email);
        if (existingUser) {
          return res("Email is already in use", 400);
        }

        const hashedPassword = await bcryptjs.hash(password, 10);
        const newUser = await userStore.create({
          username,
          email,
          password: hashedPassword,
        });

        const token = jwt.sign({ userId: newUser.id }, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });

        return res("User registered successfully", 200, {
          Cookie: `${token}; HttpOnly; Secure; Max-Age=3600; Path=/`,
        });
      }

      case "POST /auth/logout": {
        return res("Logout successful", 200, {
          Cookie: `; HttpOnly; Secure; Max-Age=0; Path=/`,
        });
      }

      default:
        return res("Route not found", 404);
    }
  } catch (error) {
    console.error("Error:", error);
    return res("Internal Server Error", 500);
  }
};
