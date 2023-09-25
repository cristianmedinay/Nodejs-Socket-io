"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserController = void 0;
/* import User, {IUser} from '../models/user' */
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const fs_1 = __importDefault(require("fs"));
const publicityKey = fs_1.default.readFileSync('jwtRS256.key');
const signOptions = {
    expiresIn: "10m",
    algorithm: "RS256"
};
function createToken(user) {
    const signedToken = jsonwebtoken_1.default.sign({ id: user.id, email: user.email }, publicityKey, signOptions);
    const obj = {
        expiresIn: "10m",
        token: signedToken
    };
    return obj;
}
function refreshToken(user) {
    const refreshToken = jsonwebtoken_1.default.sign({ id: user.id, email: user.email }, publicityKey, signOptions);
    const obj = {
        expiresIn: "10m",
        token: refreshToken
    };
    return obj;
}
class UserController {
    constructor(userUseCase) {
        this.userUseCase = userUseCase;
        this.getUser = (req, res) => __awaiter(this, void 0, void 0, function* () {
            const { email } = req.body;
            /* console.log(req.query) */
            const user = yield this.userUseCase.getDetaiEmail(`${email}`);
            if (!user) {
                return res.status(400).json({ msg: 'el usuario no existe' });
            }
            res.send({ user });
        });
        //registrarse
        this.signUp = (req, res) => __awaiter(this, void 0, void 0, function* () {
            console.log(req.body);
            if (!req.body.email || !req.body.password) {
                return res.status(400).json({ msg: 'Porfavor envia tu email y contraseña' });
            }
            const user = yield this.userUseCase.getDetaiEmail(req.body.email);
            if (user) {
                return res.status(400).json({ msg: 'El usuario existe' });
            }
            return yield this.userUseCase.registerUsers(req.body).then(result => {
                return res.status(201).json(result);
            }).catch(err => {
                return res.sendStatus(400).send({
                    message: err.message || "some error occured"
                });
            });
        });
        //login
        this.signIn = (req, res) => __awaiter(this, void 0, void 0, function* () {
            if (!req.body.email || !req.body.password) {
                return res.status(400).json({ msg: 'Porfavor envia tu email y contraseña' });
            }
            const user = yield this.userUseCase.getDetaiEmail(req.body.email);
            console.log(user);
            if (!user) {
                return res.status(400).json({ msg: 'el usuario no existe', status: false });
            }
            const password = req.body.password;
            const isMatch = yield user.comparePasswords(password);
            const newUser = {
                uuid: user.uuid,
                name: user.name,
                email: user.email
            };
            if (!isMatch) {
                return res.status(400).json({ msg: 'el correo o contraseña son incorrectas', status: false });
            }
            const tokenObject = createToken(user);
            let oldTokens = user.tokens || [];
            if (oldTokens.length) {
                oldTokens = oldTokens.filter((tim) => {
                    const timeDiff = (Date.now() - parseInt(tim.signedAt)) / 1000;
                    if (timeDiff < 86400) {
                        return tim;
                    }
                });
            }
            yield this.userUseCase.updateToken(true, user._id, oldTokens, tokenObject);
            return res
                .cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'strict' })
                .header('Authorization', tokenObject.token)
                .status(200).json({ token: tokenObject.token, status: true, expireTime: tokenObject.expiresIn, user: newUser });
        });
        this.isAuth = (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            if (req.headers && req.headers.authorization) {
                const token = req.headers.authorization.split(' ')[1];
                console.log(req);
                /* try {
                  const decode:any = jwt.verify(token, publicityKey,signOptions);
                  const user = await this.userUseCase.getUserId(decode.id);
                  console.log(user)
                  if (!user) {
                    return res.json({ success: false, message: 'unauthorized access!' });
                  }
                  req.user = user;
                  next();
                } catch (error:any) {
                  if (error.name === 'JsonWebTokenError') {
                    return res.json({ success: false, message: 'unauthorized access!' });
                  }
                  if (error.name === 'TokenExpiredError') {
                    return res.json({
                      success: false,
                      message: 'sesson expired try sign in!',
                    });
                  }
                  res.json({ success: false, message: 'Internal server error!' });
                }    */
            }
            else {
                res.json({ success: false, message: 'unauthorized access!' });
            }
        });
        this.signOut = (req, res) => __awaiter(this, void 0, void 0, function* () {
            if (req.headers && req.headers.authorization) {
                const token = req.headers.authorization.split(' ')[1];
                const { tokens, _id } = req.user;
                if (!token) {
                    return res
                        .status(401)
                        .json({ success: false, message: 'Authorization fail!' });
                }
                const newTokens = tokens.filter((t) => t.tokenObject.token !== token);
                console.log(newTokens);
                jsonwebtoken_1.default.decode;
                yield this.userUseCase.updateToken(false, _id, newTokens);
                res.json({ success: true, message: 'Sign out successfully!' });
            }
        });
    }
}
exports.UserController = UserController;
