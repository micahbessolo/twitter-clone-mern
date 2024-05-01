import { generateTokenAndSetCookie } from "../lib/utils/generateToken.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";

export const signup = async (req, res) =>
{
    try {
        const { username, fullName, password, email } = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: "Invalid email" });
        }

        const existingUser = await User.findOne({ username: username });
        if (existingUser)
        {
            return res.status(400).json({ error: "Username already exists" });
        }

        const existingEmail = await User.findOne({ email: email });
        if (existingUser)
        {
            return res.status(400).json({ error: "Email already exists" });
        }

        if (password.length < 6)
        {
            return res.status(400).json({ error: "Password must be at least 6 characters long" });
        }
        // hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        const newUser = new User({
            username,
            fullName,
            password: hashedPassword,
            email
        });

        if (newUser)
        {
            generateTokenAndSetCookie(newUser._id, res);
            await newUser.save();

            res.status(201).json({
                _id: newUser._id,
                username: newUser.username,
                fullName: newUser.fullName,
                email: newUser.email,
                followers: newUser.followers,
                following: newUser.following,
                profileImg: newUser.profileImg,
                coverImg: newUser.coverImg,
            });
        } else {
            res.status(400).json({ error: "Invalid user data" });
        }
    }
    catch (error)
    {
        console.error(`Error in signup: ${error.message}`);
        res.status(500).json({ error: "Internal server error" });
    }
}

export const login = async (req, res) =>
{
    res.json({
        data: "You hit the login enpoint"
    });
}

export const logout = async (req, res) =>
{
    res.json({
        data: "You hit the logout enpoint"
    });
}