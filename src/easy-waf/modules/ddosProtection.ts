// src/protection/ddosProtection.ts
import geoip from 'geoip-lite';

interface DDoSProtectionConfig {
    maxRequestsPerUser: number;
    ddosThreshold: number;
    ddosTimeout: number;
    userBanTimeout: number;
    userDataTimeout: number;  // Window duration for rate limiting
    mainCountry: string;
    supportMail: string;
    mainInfo: string;
    enableLogging: boolean;
}

interface UserData {
    count: number;
    firstRequest: number;    // Timestamp of first request in window
    lastRequest: number;     // Timestamp of last request
    banned: boolean;
    banExpiry?: number;
}

class DDoSProtection {
    private usersMap = new Map<string, UserData>();
    private ddosCount = 0;
    private isDDoSAttack = false;
    private config: DDoSProtectionConfig;

    constructor(config: DDoSProtectionConfig) {
        this.config = config;
        this.startDDoSMonitoring();
        this.startCleanupTask();
    }

    private startDDoSMonitoring() {
        setInterval(() => {
            if (!this.isDDoSAttack && this.ddosCount > this.config.ddosThreshold) {
                this.isDDoSAttack = true;

                // Log DDoS attack detection
                if (this.config.enableLogging) {
                    for (let i = 0; i < 5; i++) {
                        console.log('[DEFENSE SYSTEM] WARNING DDOS ATTACK DETECTED!');
                    }
                }

                // Reset after timeout
                setTimeout(() => {
                    if (this.config.enableLogging) {
                        for (let i = 0; i < 5; i++) {
                            console.log('[DEFENSE SYSTEM] DDOS ATTACKS NOW STOPPED!');
                        }
                    }
                    this.isDDoSAttack = false;
                }, this.config.ddosTimeout);
            }
            this.ddosCount = 0;
        }, 2000);
    }

    private startCleanupTask() {
        // Clean up expired entries every minute
        setInterval(() => {
            const now = Date.now();
            for (const [key, userData] of this.usersMap.entries()) {
                // Remove expired bans
                if (userData.banned && userData.banExpiry && now > userData.banExpiry) {
                    this.usersMap.delete(key);
                    if (this.config.enableLogging) {
                        console.log(`[DDOS] Ban expired and removed: ${key}`);
                    }
                }
                // Remove inactive users (no requests for 2x window time)
                else if (!userData.banned && (now - userData.lastRequest) > (this.config.userDataTimeout * 2)) {
                    this.usersMap.delete(key);
                    if (this.config.enableLogging) {
                        console.log(`[DDOS] Inactive user removed: ${key}`);
                    }
                }
            }
        }, 60000);
    }

    private async extractIP(req: any): Promise<string> {
        // Cloudflare support
        if (req.headers['cf-connecting-ip']) {
            return req.headers['cf-connecting-ip'];
        }

        // Extract IP from headers
        let ip = (req.headers['x-forwarded-for'] || '')
            .split(',')[0]           // Get first IP in chain
            .replace(/:\d+$/, '')    // Remove port number
            .trim() || 
            req.connection?.remoteAddress || 
            req.socket?.remoteAddress ||
            req.ip;

        // Normalize IP format
        if (ip?.includes('::ffff:')) {
            ip = ip.split(':').pop() || ip;
        }

        // Handle localhost
        if (ip === '127.0.0.1' || ip === '::1') {
            return '0.0.0.0'; // Use consistent dummy IP
        }

        return ip || '0.0.0.0';
    }

    private async getGeoLocation(ip: string, req: any): Promise<string> {
        // Cloudflare header
        if (req.headers['cf-ipcountry']) {
            return req.headers['cf-ipcountry'];
        }

        // GeoIP lookup
        const lookedUpIP = geoip.lookup(ip);
        return lookedUpIP?.country || 'UNKNOWN';
    }

    async checkRequest(req: any): Promise<{ blocked: boolean; reason?: string; message?: any }> {
        try {
            const ipAddress = await this.extractIP(req);
            const geo = await this.getGeoLocation(ipAddress, req);
            const userKey = `veri_${ipAddress}`;
            const now = Date.now();

            // Check existing user data
            let userData = this.usersMap.get(userKey);

            // Handle banned users
            if (userData?.banned) {
                if (userData.banExpiry && now < userData.banExpiry) {
                    if (this.config.enableLogging) {
                        const remaining = Math.ceil((userData.banExpiry - now) / 1000);
                        console.log(`[DDOS] Blocked banned IP: ${ipAddress} (${remaining}s remaining)`);
                    }
                    return {
                        blocked: true,
                        reason: 'USER_BANNED',
                        message: {
                            WARNING: 'Your IP has been temporarily blocked',
                            Reason: 'Excessive request rate',
                            'Block Expires In': `${Math.ceil((userData.banExpiry - now) / 1000)} seconds`,
                            'Support Mail': this.config.supportMail
                        }
                    };
                } 
                // Ban expired - reset user
                this.usersMap.delete(userKey);
                userData = undefined;
            }

            // Initialize new user
            if (!userData) {
                userData = {
                    count: 0,
                    firstRequest: now,
                    lastRequest: now,
                    banned: false
                };
                this.usersMap.set(userKey, userData);
            }

            // Check if window has expired
            const windowExpired = (now - userData.firstRequest) > this.config.userDataTimeout;
            
            // Reset counter if window expired
            if (windowExpired) {
                userData.count = 0;
                userData.firstRequest = now;
            }

            // Update request counts
            userData.count++;
            userData.lastRequest = now;

            // Check if over limit
            if (userData.count > this.config.maxRequestsPerUser) {
                // Apply ban
                userData.banned = true;
                userData.banExpiry = now + this.config.userBanTimeout;

                if (this.config.enableLogging) {
                    console.log(`[DDOS] Banned IP: ${ipAddress} (${userData.count} requests in ${Math.ceil((now - userData.firstRequest)/1000)}s)`);
                }

                return {
                    blocked: true,
                    reason: 'RATE_LIMIT_EXCEEDED',
                    message: {
                        WARNING: 'Request rate limit exceeded',
                        'Max Requests': this.config.maxRequestsPerUser,
                        'Your Requests': userData.count,
                        'Block Duration': `${Math.ceil(this.config.userBanTimeout / 1000)} seconds`,
                        'Support Mail': this.config.supportMail
                    }
                };
            }

            // Handle foreign requests during normal operation
            if (geo !== this.config.mainCountry) {
                if (this.isDDoSAttack) {
                    return {
                        blocked: true,
                        reason: 'GLOBAL_DDOS',
                        message: {
                            WARNING: 'Service temporarily restricted',
                            Reason: 'DDoS protection active',
                            'Support Mail': this.config.supportMail
                        }
                    };
                }
                this.ddosCount += 1;
            }

            // Log request
            if (this.config.enableLogging) {
                const windowProgress = Math.ceil((now - userData.firstRequest) / 1000);
                console.log(
                    `[DDOS-LOG] ${ipAddress} (${geo}) | ` +
                    `Requests: ${userData.count}/${this.config.maxRequestsPerUser} | ` +
                    `Window: ${windowProgress}s/${Math.ceil(this.config.userDataTimeout/1000)}s | ` +
                    `Global: ${this.ddosCount}/${this.config.ddosThreshold}`
                );
            }

            return { blocked: false };
        } catch (error) {
            console.error('[DDOS] Protection error:', error);
            return { blocked: false };
        }
    }

    // Getter methods for monitoring
    get isDDoSActive(): boolean {
        return this.isDDoSAttack;
    }

    get currentDDoSCount(): number {
        return this.ddosCount;
    }

    get activeUsers(): number {
        return this.usersMap.size;
    }
}

export default DDoSProtection;