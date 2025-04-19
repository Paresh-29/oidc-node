import express from 'express';
import { googleCallback, googleLogin } from '../controllers/auth.controller.js';

const router = express.Router();

router.get('/google', googleLogin);
router.get('/google/callback', googleCallback);

export default router;
