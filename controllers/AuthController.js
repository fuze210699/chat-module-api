import jwt from "jsonwebtoken";
import User from "../models/UserModel.js";
import { compare } from "bcrypt";

const maxAge = 3 * 24 * 60 * 60 * 1000;

const createToken = (email, userId) => {
  return jwt.sign({email, userId}, process.env.JWT_KEY, {expiresIn: maxAge})
}

export const signup = async (request, response) => {
  try {
    const { email, password } = request.body;
    if (!email || !password) {
      return response.status(400).json({ error: "Email and Password are required" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return response.status(409).json({ error: "User with this email already exists" });
    }

    const user = await User.create({ email, password });

    response.cookie("jwt", createToken(email, user.id), {
      maxAge,
      secure: true,
      sameSite: "None"
    });

    return response.status(201).json({
      user: {
        id: user.id,
        email: user.email,
        profileSetup: user.profileSetup
      }
    });
  } catch (error) {
    console.error("Signup error:", error);
    if (error.name === 'ValidationError') {
      return response.status(400).json({ error: error.message });
    }
    return response.status(500).json({ error: "Internal Server Error" });
  }
}

export const login = async (request, response) => {
  try {
    const { email, password } = request.body;
    if (!email || !password) {
      return response.status(400).json({ error: "Email and Password are required" });
    }

    // Check if user already exists
    const user = await User.findOne({ email });
    if (!user) {
      return response.status(404).json({ error: "User with the given email not found" });
    }
    const auth = await compare(password, user.password);

    if(!auth){
      return response.status(400).send("Password is incorrect")
    }

    response.cookie("jwt", createToken(email, user.id), {
      maxAge,
      secure: true,
      sameSite: "None"
    });

    return response.status(201).json({
      user: {
        id: user.id,
        email: user.email,
        profileSetup: user.profileSetup,
        firstName: user.firstName,
        lastName: user.lastName,
        image: user.image,
        color: user.color,
      }
    });
  } catch (error) {
    return response.status(500).json({ error: "Internal Server Error" });
  }
}
