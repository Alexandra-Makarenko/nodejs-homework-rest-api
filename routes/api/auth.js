const express = require("express");

const ctrl = require("../../controllers/auth")

const {validation, authenticate,upload} = require("../../middlewares")

const {schemas} = require("../../models/user")

const router = express.Router();

// register
router.post("/users/signup", validation(schemas.registerSchema), ctrl.register);

router.get("/verify/:verificationToken", ctrl.verify);

router.post("/users/verify", validation(schemas.verifySchema), ctrl.verifyRepeat);

// signin
router.post("/users/login", validation(schemas.loginSchema), ctrl.login);

router.get("/users/current", authenticate, ctrl.getCurrent);

router.post("/users/logout", authenticate, ctrl.logout);

router.patch("/users/avatars", authenticate, upload.single("avatar"), ctrl.updateAvatar)



module.exports = router;