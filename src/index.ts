// src/index.ts
import express from 'express';

// import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { config } from 'dotenv';
// import mysql from 'mysql2/promise';
// import bcrypt from 'bcrypt';
// import jwt from 'jsonwebtoken';
// @ts-ignore
import { body, validationResult, query } from 'express-validator';
import easyWaf from './easy-waf/index';
import type { EasyWaf } from './easy-waf/types';
import DDoSProtection from './easy-waf/modules/ddosProtection';

// Load environment variables
config();

// Types
// interface User {
//     id: number;
//     username: string;
//     email: string;
//     password: string;
//     created_at: Date;
//     updated_at: Date;
//     is_active: boolean;
// }

// interface JWTPayload {
//     userId: number;
//     username: string;
//     email: string;
// }

// interface AuthenticatedRequest extends express.Request {
//     user?: JWTPayload;
// }

// Database connection
// const createDbConnection = async () => {
//     try {
//         const connection = await mysql.createConnection({
//             host: process.env['DB_HOST'] || 'localhost',
//             port: parseInt(process.env['DB_PORT'] || '3306'),
//             user: process.env['DB_USER'] || 'root',
//             password: process.env['DB_PASSWORD'] || '',
//             database: process.env['DB_NAME'] || 'waf_protection',
//             charset: 'utf8mb4',
//             timezone: '+00:00',
//         });

//         console.log('✅ Connected to MySQL database');
//         return connection;
//     } catch (error) {
//         console.error('❌ Database connection failed:', error);
//         process.exit(1);
//     }
// };

// // Initialize database connection
// let db: mysql.Connection;

// const initDatabase = async () => {
//     db = await createDbConnection();

//     // Create tables if they don't exist
//     await db.execute(`
//     CREATE TABLE IF NOT EXISTS users (
//       id INT AUTO_INCREMENT PRIMARY KEY,
//       username VARCHAR(255) UNIQUE NOT NULL,
//       email VARCHAR(255) UNIQUE NOT NULL,
//       password VARCHAR(255) NOT NULL,
//       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
//       is_active BOOLEAN DEFAULT TRUE,
//       INDEX idx_username (username),
//       INDEX idx_email (email)
//     )
//   `);

//     await db.execute(`
//     CREATE TABLE IF NOT EXISTS attack_logs (
//       id INT AUTO_INCREMENT PRIMARY KEY,
//       ip_address VARCHAR(45) NOT NULL,
//       user_agent TEXT,
//       attack_type VARCHAR(100) NOT NULL,
//       url VARCHAR(500) NOT NULL,
//       payload TEXT,
//       blocked BOOLEAN DEFAULT TRUE,
//       timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//       country VARCHAR(10),
//       INDEX idx_ip_address (ip_address),
//       INDEX idx_attack_type (attack_type),
//       INDEX idx_timestamp (timestamp),
//       INDEX idx_blocked (blocked)
//     )
//   `);

//     await db.execute(`
//     CREATE TABLE IF NOT EXISTS user_sessions (
//       id INT AUTO_INCREMENT PRIMARY KEY,
//       user_id INT NOT NULL,
//       token_hash VARCHAR(255) NOT NULL,
//       expires_at TIMESTAMP NOT NULL,
//       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//       FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
//       INDEX idx_user_id (user_id),
//       INDEX idx_token_hash (token_hash),
//       INDEX idx_expires_at (expires_at)
//     )
//   `);

//     console.log('✅ Database tables initialized');
// };

const app = express();
const PORT = process.env['PORT'] || 9000;
// const JWT_SECRET = process.env['JWT_SECRET'] || 'your-super-secret-jwt-key-change-this-in-production';
// const JWT_REFRESH_SECRET = process.env['JWT_REFRESH_SECRET'] || 'your-refresh-secret-key';

// Configuration
const appConfig = {
    supportMail: process.env['SUPPORT_MAIL'] || 'patelanshu702@gmail.com',
    mainCountry: process.env['MAIN_COUNTRY'] || 'IN',
    mainInfo: process.env['MAIN_INFO'] || 'You can send an e-mail in english.',
    ddosLog: process.env['DDOS_LOG'] === 'true',
    disableDdosProtection: process.env['DISABLE_DDOS'] === 'true',
    protectedUrls: ['/', '/error', '/admin', '/auth', '/user', '/logs', '/health'], // /health is included
};

// Initialize DDoS Protection
const ddosProtection = new DDoSProtection({
    maxRequestsPerUser: 100, // 100 requests per user (keep this)
    ddosThreshold: 200, // 200 for global DDoS detection
    ddosTimeout: 30000, // 30s DDoS mode
    userBanTimeout: 600000, // 10-minute ban
    userDataTimeout: 600000, // 10-minute window (600k ms)
    mainCountry: appConfig.mainCountry,
    supportMail: appConfig.supportMail,
    mainInfo: appConfig.mainInfo,
    enableLogging: appConfig.ddosLog,
});

// Security middleware
app.use(helmet());
app.use(
    cors({
        origin: process.env['CLIENT_URL'] || 'http://localhost:5173',
        credentials: true,
    }),
);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Rate limiting
// const limiter = rateLimit({
//     windowMs: 15 * 60 * 1000, // 15 minutes
//     max: 100,
//     message: 'Too many requests from this IP, please try again later.',
//     standardHeaders: true,
//     legacyHeaders: false,
// });
// app.use(limiter);

// WAF Configuration
const wafConfig: EasyWaf.Config = {
    dryMode: false,
    disableLogging: false,
    allowedHTTPMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
    trustProxy: true,
    modules: {
        sqlInjection: { enabled: true },
        xss: { enabled: true },
        directoryTraversal: { enabled: true },
        noSqlInjection: { enabled: true },
        xmlInjection: { enabled: true },
        crlfInjection: { enabled: true },
        prototypePollution: { enabled: true },
        httpParameterPollution: { enabled: true },
        openRedirect: { enabled: true },
        badBots: { enabled: true },
        fakeCrawlers: { enabled: true },
        blockTorExitNodes: { enabled: false },
    },
    postBlockHook: async (req: any, moduleName: string, ip: string) => {
        console.log(`🚫 WAF Blocked ${moduleName} attack from ${ip} - URL: ${req.url}`);

        // Log attack to database
        // try {
        //     await db.execute('INSERT INTO attack_logs (ip_address, user_agent, attack_type, url, payload, blocked) VALUES (?, ?, ?, ?, ?, ?)', [
        //         ip,
        //         req.headers['user-agent'] || '',
        //         moduleName,
        //         req.url,
        //         JSON.stringify(req.body),
        //         true,
        //     ]);
        // } catch (error) {
        //     console.error('Error logging attack:', error);
        // }
    },
    preBlockHook: async (_req: any, _moduleName: string, _ip: string) => {
        return true;
    },
};

// Initialize WAF middleware
const wafMiddleware = easyWaf(wafConfig);

// Authentication middleware
// const authenticateToken = async (req: AuthenticatedRequest, res: express.Response, next: express.NextFunction) => {
//     const authHeader = req.headers['authorization'];
//     const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

//     if (!token) {
//         return res.status(401).json({ error: 'Access token required' });
//     }

//     try {
//         const decoded = jwt.verify(token, JWT_SECRET) as JWTPayload;

//         // Check if user still exists and is active
//         const [rows] = await db.execute('SELECT id, username, email, is_active FROM users WHERE id = ? AND is_active = TRUE', [decoded.userId]);

//         if (!Array.isArray(rows) || rows.length === 0) {
//             return res.status(401).json({ error: 'Invalid token' });
//         }

//         req.user = decoded;
//         next();
//     } catch (error) {
//         console.error('Token verification error:', error);
//         return res.status(403).json({ error: 'Invalid token' });
//     }
// };

// Combined protection middleware
app.use(async (req, res, next) => {
    const url = req.originalUrl;

    // Check if URL needs protection
    if (appConfig.protectedUrls.some((protectedUrl) => url.startsWith(protectedUrl))) {
        // First run DDoS protection (if not disabled)
        if (!appConfig.disableDdosProtection) {
            const ddosResult = await ddosProtection.checkRequest(req);

            if (ddosResult.blocked && ddosResult.reason === 'GLOBAL_DDOS') {
                
            } else if (ddosResult.blocked) {
                return res.status(429).json(ddosResult.message);
            }
        }

        // Then run WAF protection
        wafMiddleware(req, res, (error?: any) => {
            if (error) {
                console.error('WAF middleware error:', error);
                return res.status(500).json({ error: 'Internal server error' });
            }
            return next();
        });
    } else {
        // For non-protected URLs, still run WAF but skip DDoS protection
        wafMiddleware(req, res, (error?: any) => {
            if (error) {
                console.error('WAF middleware error:', error);
                return res.status(500).json({ error: 'Internal server error' });
            }
            return next();
        });
    }
});

// // Utility functions
// const generateTokens = (user: { id: number; username: string; email: string }) => {
//     const payload: JWTPayload = {
//         userId: user.id,
//         username: user.username,
//         email: user.email,
//     };

//     const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
//     const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: '7d' });

//     return { accessToken, refreshToken };
// };

// const hashPassword = async (password: string): Promise<string> => {
//     return await bcrypt.hash(password, 12);
// };

// const comparePassword = async (password: string, hash: string): Promise<boolean> => {
//     return await bcrypt.compare(password, hash);
// };

// // Validation middleware
// const validateSignup = [
//     body('username')
//         .isLength({ min: 3, max: 50 })
//         .withMessage('Username must be 3-50 characters')
//         .matches(/^[a-zA-Z0-9_]+$/)
//         .withMessage('Username can only contain letters, numbers, and underscores'),
//     body('email').isEmail().withMessage('Please provide a valid email').normalizeEmail(),
//     body('password').isLength({ min: 6 }),
// ];

// const validateLogin = [body('email').isEmail().normalizeEmail(), body('password').isLength({ min: 1 })];

// // Auth Routes
// app.post('/auth/signup', validateSignup, async (req: express.Request, res: express.Response) => {
//     try {
//         console.log('📝 Signup request received:', {
//             body: req.body,
//             headers: req.headers['content-type'],
//         });

//         const errors = validationResult(req);
//         if (!errors.isEmpty()) {
//             console.log('❌ Validation errors:', errors.array());
//             return res.status(400).json({ errors: errors.array() });
//         }

//         const { username, email, password } = req.body;

//         // Check if user already exists
//         const [existingUsers] = await db.execute('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);

//         if (Array.isArray(existingUsers) && existingUsers.length > 0) {
//             return res.status(400).json({ error: 'Username or email already exists' });
//         }

//         // Hash password and create user
//         const hashedPassword = await hashPassword(password);
//         const [result] = await db.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);

//         const insertResult = result as mysql.ResultSetHeader;
//         const userId = insertResult.insertId;

//         // Generate tokens
//         const user = { id: userId, username, email };
//         const { accessToken, refreshToken } = generateTokens(user);

//         // Set refresh token as httpOnly cookie
//         res.cookie('refreshToken', refreshToken, {
//             httpOnly: true,
//             secure: process.env['NODE_ENV'] === 'production',
//             sameSite: 'strict',
//             maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
//         });

//         res.status(201).json({
//             message: 'User created successfully',
//             user: { id: userId, username, email },
//             accessToken,
//         });
//     } catch (error) {
//         console.error('Signup error:', error);
//         res.status(500).json({ error: 'Internal server error' });
//     }
// });

// app.post('/auth/login', validateLogin, async (req: express.Request, res: express.Response) => {
//     try {
//         const errors = validationResult(req);
//         if (!errors.isEmpty()) {
//             return res.status(400).json({ errors: errors.array() });
//         }

//         const { email, password } = req.body;

//         // Find user
//         const [users] = await db.execute('SELECT id, username, email, password, is_active FROM users WHERE email = ?', [email]);

//         if (!Array.isArray(users) || users.length === 0) {
//             return res.status(401).json({ error: 'Invalid credentials' });
//         }

//         const user = users[0] as User;

//         if (!user.is_active) {
//             return res.status(401).json({ error: 'Account is deactivated' });
//         }

//         // Check password
//         const isPasswordValid = await comparePassword(password, user.password);
//         if (!isPasswordValid) {
//             return res.status(401).json({ error: 'Invalid credentials' });
//         }

//         // Generate tokens
//         const { accessToken, refreshToken } = generateTokens(user);

//         // Set refresh token as httpOnly cookie
//         res.cookie('refreshToken', refreshToken, {
//             httpOnly: true,
//             secure: process.env['NODE_ENV'] === 'production',
//             sameSite: 'strict',
//             maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
//         });

//         res.json({
//             message: 'Login successful',
//             user: { id: user.id, username: user.username, email: user.email },
//             accessToken,
//         });
//     } catch (error) {
//         console.error('Login error:', error);
//         res.status(500).json({ error: 'Internal server error' });
//     }
// });

// app.post('/auth/logout', authenticateToken, async (_req: AuthenticatedRequest, res) => {
//     try {
//         // Clear refresh token cookie
//         res.clearCookie('refreshToken');

//         // In a production app, you might want to blacklist the token
//         // or remove it from a token store

//         res.json({ message: 'Logout successful' });
//     } catch (error) {
//         console.error('Logout error:', error);
//         res.status(500).json({ error: 'Internal server error' });
//     }
// });

// app.get('/auth/me', authenticateToken, async (req: AuthenticatedRequest, res) => {
//     try {
//         const [users] = await db.execute('SELECT id, username, email, created_at, updated_at FROM users WHERE id = ?', [req.user!.userId]);

//         if (!Array.isArray(users) || users.length === 0) {
//             return res.status(404).json({ error: 'User not found' });
//         }

//         res.json({ user: users[0] });
//     } catch (error) {
//         console.error('Get current user error:', error);
//         res.status(500).json({ error: 'Internal server error' });
//     }
// });

// app.post('/auth/refresh', async (req, res) => {
//     try {
//         const refreshToken = req.cookies.refreshToken;

//         if (!refreshToken) {
//             return res.status(401).json({ error: 'Refresh token required' });
//         }

//         const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as JWTPayload;

//         // Check if user still exists and is active
//         const [users] = await db.execute('SELECT id, username, email, is_active FROM users WHERE id = ? AND is_active = TRUE', [decoded.userId]);

//         if (!Array.isArray(users) || users.length === 0) {
//             return res.status(401).json({ error: 'Invalid refresh token' });
//         }

//         const user = users[0] as User;
//         const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

//         // Set new refresh token as httpOnly cookie
//         res.cookie('refreshToken', newRefreshToken, {
//             httpOnly: true,
//             secure: process.env['NODE_ENV'] === 'production',
//             sameSite: 'strict',
//             maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
//         });

//         res.json({
//             accessToken,
//             user: { id: user.id, username: user.username, email: user.email },
//         });
//     } catch (error) {
//         console.error('Refresh token error:', error);
//         res.status(401).json({ error: 'Invalid refresh token' });
//     }
// });

// // User Routes
// app.get('/user/info', authenticateToken, async (req: AuthenticatedRequest, res) => {
//     try {
//         const [users] = await db.execute('SELECT id, username, email, created_at, updated_at FROM users WHERE id = ?', [req.user!.userId]);

//         if (!Array.isArray(users) || users.length === 0) {
//             return res.status(404).json({ error: 'User not found' });
//         }

//         res.json({ user: users[0] });
//     } catch (error) {
//         console.error('Get user info error:', error);
//         res.status(500).json({ error: 'Internal server error' });
//     }
// });

// app.put(
//     '/user/info',
//     authenticateToken,
//     [
//         body('username')
//             .optional()
//             .isLength({ min: 3, max: 50 })
//             .matches(/^[a-zA-Z0-9_]+$/),
//         body('email').optional().isEmail().normalizeEmail(),
//     ],
//     async (req: AuthenticatedRequest, res: express.Response) => {
//         try {
//             const errors = validationResult(req);
//             if (!errors.isEmpty()) {
//                 return res.status(400).json({ errors: errors.array() });
//             }

//             const { username, email } = req.body;
//             const userId = req.user!.userId;

//             // Check if new username or email already exists (excluding current user)
//             if (username || email) {
//                 const [existingUsers] = await db.execute('SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?', [
//                     username || '',
//                     email || '',
//                     userId,
//                 ]);

//                 if (Array.isArray(existingUsers) && existingUsers.length > 0) {
//                     return res.status(400).json({ error: 'Username or email already exists' });
//                 }
//             }

//             // Update user
//             const updates: string[] = [];
//             const values: any[] = [];

//             if (username) {
//                 updates.push('username = ?');
//                 values.push(username);
//             }

//             if (email) {
//                 updates.push('email = ?');
//                 values.push(email);
//             }

//             if (updates.length === 0) {
//                 return res.status(400).json({ error: 'No updates provided' });
//             }

//             updates.push('updated_at = CURRENT_TIMESTAMP');
//             values.push(userId);

//             await db.execute(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values);

//             // Get updated user
//             const [users] = await db.execute('SELECT id, username, email, created_at, updated_at FROM users WHERE id = ?', [userId]);

//             res.json({
//                 message: 'User updated successfully',
//                 user: (users as any[])[0],
//             });
//         } catch (error) {
//             console.error('Update user error:', error);
//             res.status(500).json({ error: 'Internal server error' });
//         }
//     },
// );

// app.delete('/user/account', authenticateToken, async (req: AuthenticatedRequest, res) => {
//     try {
//         const userId = req.user!.userId;

//         // Soft delete - set is_active to false
//         await db.execute('UPDATE users SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [userId]);

//         // Clear refresh token cookie
//         res.clearCookie('refreshToken');

//         res.json({ message: 'Account deleted successfully' });
//     } catch (error) {
//         console.error('Delete account error:', error);
//         res.status(500).json({ error: 'Internal server error' });
//     }
// });

// // Logs Routes
// app.get(
//     '/logs',
//     authenticateToken,
//     [
//         query('page').optional().isInt({ min: 1 }),
//         query('limit').optional().isInt({ min: 1, max: 100 }),
//         query('attack_type').optional().isString(),
//         query('start_date').optional().isISO8601(),
//         query('end_date').optional().isISO8601(),
//     ],
//     async (req: AuthenticatedRequest, res: express.Response) => {
//         try {
//             const errors = validationResult(req);
//             if (!errors.isEmpty()) {
//                 return res.status(400).json({ errors: errors.array() });
//             }

//             const page = parseInt(req.query['page'] as string) || 1;
//             const limit = parseInt(req.query['limit'] as string) || 50;
//             const offset = (page - 1) * limit;
//             const attackType = req.query['attack_type'] as string;
//             const startDate = req.query['start_date'] as string;
//             const endDate = req.query['end_date'] as string;

//             // Build query
//             let whereClause = 'WHERE 1=1';
//             const queryParams: any[] = [];

//             if (attackType) {
//                 whereClause += ' AND attack_type = ?';
//                 queryParams.push(attackType);
//             }

//             if (startDate) {
//                 whereClause += ' AND timestamp >= ?';
//                 queryParams.push(startDate);
//             }

//             if (endDate) {
//                 whereClause += ' AND timestamp <= ?';
//                 queryParams.push(endDate);
//             }

//             // Get total count
//             const [countResult] = await db.execute(`SELECT COUNT(*) as total FROM attack_logs ${whereClause}`, queryParams);
//             const total = (countResult as any[])[0].total;

//             // Get logs
//             const [logs] = await db.execute(`SELECT * FROM attack_logs ${whereClause} ORDER BY timestamp DESC LIMIT ? OFFSET ?`, [
//                 ...queryParams,
//                 limit,
//                 offset,
//             ]);

//             res.json({
//                 logs,
//                 pagination: {
//                     page,
//                     limit,
//                     total,
//                     totalPages: Math.ceil(total / limit),
//                 },
//             });
//         } catch (error) {
//             console.error('Get logs error:', error);
//             res.status(500).json({ error: 'Internal server error' });
//         }
//     },
// );

// app.get(
//     '/logs/recent',
//     authenticateToken,
//     [query('limit').optional().isInt({ min: 1, max: 100 })],
//     async (req: AuthenticatedRequest, res: express.Response) => {
//         try {
//             const limit = parseInt(req.query['limit'] as string) || 20;

//             const [logs] = await db.execute('SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT ?', [limit]);

//             res.json({ logs });
//         } catch (error) {
//             console.error('Get recent logs error:', error);
//             res.status(500).json({ error: 'Internal server error' });
//         }
//     },
// );

// app.get('/logs/stats', authenticateToken, async (_req: AuthenticatedRequest, res: express.Response) => {
//     try {
//         // Get attack counts by type
//         const [attackTypes] = await db.execute(`
//       SELECT attack_type, COUNT(*) as count
//       FROM attack_logs
//       WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
//       GROUP BY attack_type
//       ORDER BY count DESC
//     `);

//         // Get attacks by hour for last 24 hours
//         const [hourlyStats] = await db.execute(`
//       SELECT
//         DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') as hour,
//         COUNT(*) as count
//       FROM attack_logs
//       WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
//       GROUP BY hour
//       ORDER BY hour
//     `);

//         // Get top attacking IPs
//         const [topIPs] = await db.execute(`
//       SELECT ip_address, COUNT(*) as count
//       FROM attack_logs
//       WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
//       GROUP BY ip_address
//       ORDER BY count DESC
//       LIMIT 10
//     `);

//         res.json({
//             attackTypes,
//             hourlyStats,
//             topIPs,
//         });
//     } catch (error) {
//         console.error('Get attack stats error:', error);
//         res.status(500).json({ error: 'Internal server error' });
//     }
// });

// app.get(
//     '/logs/type/:attackType',
//     authenticateToken,
//     [query('page').optional().isInt({ min: 1 }), query('limit').optional().isInt({ min: 1, max: 100 })],
//     async (req: AuthenticatedRequest, res: express.Response) => {
//         try {
//             const attackType = req.params['attackType'];
//             const page = parseInt(req.query['page'] as string) || 1;
//             const limit = parseInt(req.query['limit'] as string) || 50;
//             const offset = (page - 1) * limit;

//             // Get total count
//             const [countResult] = await db.execute('SELECT COUNT(*) as total FROM attack_logs WHERE attack_type = ?', [attackType]);
//             const total = (countResult as any[])[0].total;

//             // Get logs
//             const [logs] = await db.execute('SELECT * FROM attack_logs WHERE attack_type = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?', [
//                 attackType,
//                 limit,
//                 offset,
//             ]);

//             res.json({
//                 logs,
//                 pagination: {
//                     page,
//                     limit,
//                     total,
//                     totalPages: Math.ceil(total / limit),
//                 },
//             });
//         } catch (error) {
//             console.error('Get logs by type error:', error);
//             res.status(500).json({ error: 'Internal server error' });
//         }
//     },
// );

// app.delete('/logs/cleanup', authenticateToken, [body('days').isInt({ min: 1, max: 365 })], async (req: AuthenticatedRequest, res: express.Response) => {
//     try {
//         const errors = validationResult(req);
//         if (!errors.isEmpty()) {
//             return res.status(400).json({ errors: errors.array() });
//         }

//         const { days } = req.body;

//         const [result] = await db.execute('DELETE FROM attack_logs WHERE timestamp < DATE_SUB(NOW(), INTERVAL ? DAY)', [days]);

//         const deleteResult = result as mysql.ResultSetHeader;

//         res.json({
//             message: 'Old logs deleted successfully',
//             deletedCount: deleteResult.affectedRows,
//         });
//     } catch (error) {
//         console.error('Delete old logs error:', error);
//         res.status(500).json({ error: 'Internal server error' });
//     }
// });

// app.get('/admin', authenticateToken, (req: AuthenticatedRequest, res) => {
//     res.json({
//         message: 'Admin panel',
//         protected: true,
//         user: req.user,
//         timestamp: new Date().toISOString(),
//     });
// });

// Original routes (existing)
app.get('/', (_req, res) => {
    res.json({
        message: 'Hello World!',
        protected: true,
        timestamp: new Date().toISOString(),
    });
});

// Health check and monitoring endpoints
app.get('/health', (_req, res) => {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Health Check</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
            animation: fadeInUp 0.8s ease-out;
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .status-icon {
            font-size: 4rem;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        .status-title {
            font-size: 2.5rem;
            font-weight: 700;
            color: #2d3748;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .status-subtitle {
            font-size: 1.1rem;
            color: #718096;
            margin-bottom: 30px;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        
        .metric-card {
            background: linear-gradient(135deg, #f7fafc, #edf2f7);
            border-radius: 15px;
            padding: 20px;
            border: 1px solid rgba(0, 0, 0, 0.05);
            transition: transform 0.3s ease;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
        }
        
        .metric-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: #2d3748;
            margin-bottom: 5px;
        }
        
        .metric-label {
            font-size: 0.85rem;
            color: #718096;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .server-info {
            font-size: 1.2rem;
            font-family: 'Courier New', monospace;
            color: #4a5568;
            word-break: break-all;
        }
        
        .timestamp {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
            color: #718096;
            font-size: 0.9rem;
        }
        
        .ddos-status {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .ddos-active {
            background: rgba(245, 101, 101, 0.1);
            color: #c53030;
        }
        
        .ddos-inactive {
            background: rgba(72, 187, 120, 0.1);
            color: #38a169;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: currentColor;
            animation: blink 1.5s infinite;
        }
        
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.3; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="status-icon">🟢</div>
        <h1 class="status-title">Server is Up!</h1>
        <p class="status-subtitle">All systems operational</p>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">
                    <span class="ddos-status ddos-inactive">
                        <span class="status-dot"></span>
                        Protected
                    </span>
                </div>
                <div class="metric-label">Security Status</div>
            </div>
            <div class="metric-card">
                <div class="metric-value server-info">localhost:3000</div>
                <div class="metric-label">Server Host</div>
            </div>
        </div>
        
        <div class="timestamp">
            <div style="margin-bottom: 10px;">
            <span id="current-time">Last checked: Loading...</span>
        </div>
    </div>

    <script>
        // Update timestamp in real-time
        function updateTimestamp() {
            const now = new Date();
            document.getElementById('current-time').textContent = 
                'Last checked: ' + now.toLocaleString();
        }
        
        // Update immediately and then every second
        updateTimestamp();
        setInterval(updateTimestamp, 1000);
    </script>
</body>
</html>`;

    res.send(html);
});

app.get('/status', (_req, res) => {
    res.json({
        server: 'running',
        protections: {
            ddos: {
                active: ddosProtection.isDDoSActive,
                activeUsers: ddosProtection.activeUsers,
                currentCount: ddosProtection.currentDDoSCount,
            },
            waf: {
                modules: Object.keys(wafConfig.modules || {}).filter((key) => wafConfig.modules?.[key as keyof typeof wafConfig.modules]?.enabled),
            },
        },
        config: {
            mainCountry: appConfig.mainCountry,
            protectedUrls: appConfig.protectedUrls,
        },
    });
});

// Error handling middleware
app.use((error: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        error: 'Internal server error',
        timestamp: new Date().toISOString(),
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not found',
        path: req.originalUrl,
        timestamp: new Date().toISOString(),
    });
});

// Graceful shutdown
// process.on('SIGTERM', async () => {
//     console.log('🔄 SIGTERM received, shutting down gracefully');

//     try {
//         await db.end();
//         console.log('✅ Database connection closed');
//     } catch (error) {
//         console.error('❌ Error closing database connection:', error);
//     }

//     process.exit(0);
// });

// process.on('SIGINT', async () => {
//     console.log('🔄 SIGINT received, shutting down gracefully');

//     try {
//         await db.end();
//         console.log('✅ Database connection closed');
//     } catch (error) {
//         console.error('❌ Error closing database connection:', error);
//     }

//     process.exit(0);
// });

// Start server
const startServer = async () => {
    try {
        // Initialize database
        // await initDatabase();

        // Start server
        app.listen(PORT, () => {
            console.log(`🛡️  Enhanced WAF + DDoS Protection Service running on port ${PORT}`);
            console.log(`🌐 Access the service at http://localhost:${PORT}`);
            console.log(
                `📊 WAF Modules enabled: ${Object.keys(wafConfig.modules || {})
                    .filter((key) => wafConfig.modules?.[key as keyof typeof wafConfig.modules]?.enabled)
                    .join(', ')}`,
            );
            console.log(`🌍 Main country: ${appConfig.mainCountry}`);
            console.log(`🔒 Protected URLs: ${appConfig.protectedUrls.join(', ')}`);
            console.log(`🛡️  DDoS Protection: ${appConfig.disableDdosProtection ? '❌ DISABLED' : '✅ ENABLED'}`);
            console.log(`🔐 JWT Authentication enabled`);
            console.log(`🗄️  MySQL Database connected`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};

startServer();

export default app;
