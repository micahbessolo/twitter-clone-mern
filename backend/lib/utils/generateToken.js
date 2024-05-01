import jwt from 'jsonwebtoken';

export const generateTokenAndSetCookie = (userId, res) => {
    const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
        expiresIn: '15d'
    });

    res.cookie('jwt', token, {
        httpOnly: true, // prevent XSS attacks cross-site scripting attacks
        maxAge: 15 * 24 * 60 * 60 * 1000, // MS
        sameSite: "strict", // prevent CSRF attacks cross-site request forgery attacks
        secure: process.env.NODE_ENV !== "development", // cookie only works in https
    });
}