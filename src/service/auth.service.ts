import OktaJwtVerifier from "@okta/jwt-verifier";
import express, { Request, Response } from "express";
import * as dotenv from "dotenv";

export const authRouter = express.Router();
dotenv.config();

const oktaJwtVerifier = new OktaJwtVerifier({
    issuer: `https://${process.env.OKTA_DOMAIN}/oauth2/default`,
});

const audience = 'api://default';

export const authenticationRequired = async (req: Request | any, res: Response, next: any) => {
    const authHeader = req.headers.authorization || '';
    const match = authHeader.match(/Bearer (.+)/);
    if (!match) {
        return res.status(401).send();
    }

    try {
        const accessToken = match[1];
        if (!accessToken) {
            return res.status(401).send('Not authorized');
        }
        req.jwt = await oktaJwtVerifier.verifyAccessToken(accessToken, audience);

        next();
    } catch (err: any) {
        return res.status(401).send(err.message);
    }
};

authRouter.get("/whoami", authenticationRequired, async (req: Request | any, res: Response) => {
    res.json(req.jwt?.claims);
});
