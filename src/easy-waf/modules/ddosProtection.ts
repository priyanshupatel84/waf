// // src/protection/ddosProtection.ts
// import geoip from 'geoip-lite';

// interface DDoSProtectionConfig {
//   maxRequestsPerUser: number;
//   ddosThreshold: number;
//   ddosTimeout: number;
//   userBanTimeout: number;
//   userDataTimeout: number;
//   mainCountry: string;
//   supportMail: string;
//   mainInfo: string;
//   enableLogging: boolean;
// }

// class DDoSProtection {
//   private userRecently = new Set<string>();
//   private usersMap = new Map<string, number>();
//   private ddosCount = 0;
//   private isDDoSAttack = false;
//   private config: DDoSProtectionConfig;

//   constructor(config: DDoSProtectionConfig) {
//     this.config = config;
//     this.startDDoSMonitoring();
//   }

//   private startDDoSMonitoring() {
//     setInterval(() => {
//       if (!this.isDDoSAttack && this.ddosCount > this.config.ddosThreshold) {
//         this.isDDoSAttack = true;
        
//         // Log DDoS attack detection
//         for (let i = 0; i < 20; i++) {
//           console.log('[DEFENSE SYSTEM] WARNING DDOS ATTACK DETECTED!');
//         }
        
//         // Reset after timeout
//         setTimeout(() => {
//           for (let i = 0; i < 20; i++) {
//             console.log('[DEFENSE SYSTEM] DDOS ATTACKS NOW STOPPED!');
//           }
//           this.isDDoSAttack = false;
//         }, this.config.ddosTimeout);
//       }
//       this.ddosCount = 0;
//     }, 2000);
//   }

//   private async extractIP(req: any): Promise<string> {
//     // Check for Cloudflare IP first
//     if (req.headers['cf-connecting-ip']) {
//       return req.headers['cf-connecting-ip'];
//     }

//     // Extract IP from various headers
//     let ip = (req.headers['x-forwarded-for'] || '')
//       .replace(/:\d+$/, '') || 
//       req.connection?.remoteAddress || 
//       req.socket?.remoteAddress ||
//       req.ip;

//     if (ip?.includes('::ffff:')) {
//       ip = ip.split(':').reverse()[0];
//     }

//     // Handle localhost
//     if (ip === '127.0.0.1' || ip === '::1') {
//       return '1.11.111.1111';
//     }

//     return ip || '1.11.111.1111';
//   }

//   private async getGeoLocation(ip: string, req: any): Promise<string> {
//     // Check for Cloudflare country header first
//     if (req.headers['cf-ipcountry']) {
//       return req.headers['cf-ipcountry'];
//     }

//     // Fallback to geoip-lite
//     const lookedUpIP = geoip.lookup(ip);
//     return lookedUpIP?.country || 'UNKNOWN';
//   }

//   async checkRequest(req: any): Promise<{ blocked: boolean; reason?: string; message?: any }> {
//     try {
//       const ipAddress = await this.extractIP(req);
//       const geo = await this.getGeoLocation(ipAddress, req);
      
//       const userKey = `veri_${ipAddress}`;
//       const currentCount = this.usersMap.get(userKey) || 0;

//       // Check if user is already banned
//       if (currentCount > this.config.maxRequestsPerUser) {
//         if (currentCount > 99) {
//           return {
//             blocked: true,
//             reason: 'USER_DDOS',
//             message: {
//               WARNING: 'User DDOS Detected - Permanently Banned',
//               'Support Mail': this.config.supportMail,
//               info: this.config.mainInfo
//             }
//           };
//         }

//         if (!this.isDDoSAttack) {
//           // Temporary ban
//           setTimeout(() => {
//             if (this.config.enableLogging) {
//               console.log(`[DDOS] User Ban Deleted: ${ipAddress}`);
//             }
//             this.usersMap.set(userKey, 0);
//           }, this.config.userBanTimeout);

//           if (this.config.enableLogging) {
//             console.log(`[DDOS] User Banned: ${ipAddress}`);
//           }
          
//           this.usersMap.set(userKey, currentCount + 999);
//           return {
//             blocked: true,
//             reason: 'USER_DDOS',
//             message: {
//               WARNING: 'User DDOS Detected',
//               'Support Mail': this.config.supportMail,
//               info: this.config.mainInfo
//             }
//           };
//         }

//         // During global DDoS attack
//         if (this.config.enableLogging) {
//           console.log(`[DDOS] User Unlimited Banned: ${ipAddress}`);
//         }
        
//         this.usersMap.set(userKey, currentCount + 999);
//         return {
//           blocked: true,
//           reason: 'USER_DDOS',
//           message: {
//             WARNING: 'User DDOS Detected',
//             'Support Mail': this.config.supportMail,
//             info: this.config.mainInfo
//           }
//         };
//       }

//       // Update user request count
//       if (currentCount > 0) {
//         this.usersMap.set(userKey, currentCount + 1);
//       } else {
//         // First request from this IP
//         setTimeout(() => {
//           if (this.config.enableLogging) {
//             console.log(`[DDOS] User DATA Deleted: ${ipAddress}`);
//           }
//           this.usersMap.set(userKey, 0);
//         }, this.config.userDataTimeout);
        
//         this.usersMap.set(userKey, 1);
//       }

//       // Check for foreign country requests during normal operation
//       if (geo !== this.config.mainCountry) {
//         if (this.isDDoSAttack) {
//           return {
//             blocked: true,
//             reason: 'GLOBAL_DDOS',
//             message: {
//               WARNING: 'Global DDOS Detected',
//               Mail: this.config.supportMail
//             }
//           };
//         }
//         this.ddosCount += 1;
//       }

//       if (this.config.enableLogging) {
//         console.log(`[DDOS-LOG] Joined site: ${geo} | DOS-Count: ${currentCount}/100 | Global-DOS: ${this.ddosCount}/200`);
//       }

//       return { blocked: false };
//     } catch (error) {
//       console.error('[DDOS] Error in protection check:', error);
//       return { blocked: false };
//     }
//   }

//   // Getter methods for monitoring
//   get isDDoSActive(): boolean {
//     return this.isDDoSAttack;
//   }

//   get currentDDoSCount(): number {
//     return this.ddosCount;
//   }

//   get activeUsers(): number {
//     return this.usersMap.size;
//   }
// }

// export default DDoSProtection;


// src/protection/ddosProtection.ts
import geoip from 'geoip-lite';

interface DDoSProtectionConfig {
  maxRequestsPerUser: number;
  ddosThreshold: number;
  ddosTimeout: number;
  userBanTimeout: number;
  userDataTimeout: number;
  mainCountry: string;
  supportMail: string;
  mainInfo: string;
  enableLogging: boolean;
}

interface UserData {
  count: number;
  firstRequest: number;
  banned: boolean;
  banExpiry?: number;
}

class DDoSProtection {
  private userRecently = new Set<string>();
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
        for (let i = 0; i < 20; i++) {
          console.log('[DEFENSE SYSTEM] WARNING DDOS ATTACK DETECTED!');
        }
        
        // Reset after timeout
        setTimeout(() => {
          for (let i = 0; i < 20; i++) {
            console.log('[DEFENSE SYSTEM] DDOS ATTACKS NOW STOPPED!');
          }
          this.isDDoSAttack = false;
        }, this.config.ddosTimeout);
      }
      this.ddosCount = 0;
    }, 2000);
  }

  private startCleanupTask() {
    // Clean up expired user data every minute
    setInterval(() => {
      const now = Date.now();
      for (const [key, userData] of this.usersMap.entries()) {
        // Remove expired ban entries
        if (userData.banned && userData.banExpiry && now > userData.banExpiry) {
          this.usersMap.delete(key);
          if (this.config.enableLogging) {
            console.log(`[DDOS] Ban expired and removed: ${key}`);
          }
        }
        // Remove old user data that's past the window
        else if (!userData.banned && (now - userData.firstRequest) > this.config.userDataTimeout) {
          this.usersMap.delete(key);
          if (this.config.enableLogging) {
            console.log(`[DDOS] User data expired and removed: ${key}`);
          }
        }
      }
    }, 60000); // Run every minute
  }

  private async extractIP(req: any): Promise<string> {
    // Check for Cloudflare IP first
    if (req.headers['cf-connecting-ip']) {
      return req.headers['cf-connecting-ip'];
    }

    // Extract IP from various headers
    let ip = (req.headers['x-forwarded-for'] || '')
      .replace(/:\d+$/, '') || 
      req.connection?.remoteAddress || 
      req.socket?.remoteAddress ||
      req.ip;

    if (ip?.includes('::ffff:')) {
      ip = ip.split(':').reverse()[0];
    }

    // Handle localhost
    if (ip === '127.0.0.1' || ip === '::1') {
      return '1.11.111.1111';
    }

    return ip || '1.11.111.1111';
  }

  private async getGeoLocation(ip: string, req: any): Promise<string> {
    // Check for Cloudflare country header first
    if (req.headers['cf-ipcountry']) {
      return req.headers['cf-ipcountry'];
    }

    // Fallback to geoip-lite
    const lookedUpIP = geoip.lookup(ip);
    return lookedUpIP?.country || 'UNKNOWN';
  }

  async checkRequest(req: any): Promise<{ blocked: boolean; reason?: string; message?: any }> {
    try {
      const ipAddress = await this.extractIP(req);
      const geo = await this.getGeoLocation(ipAddress, req);
      
      const userKey = `veri_${ipAddress}`;
      const now = Date.now();
      
      let userData = this.usersMap.get(userKey);

      // Check if user is currently banned
      if (userData?.banned) {
        if (userData.banExpiry && now > userData.banExpiry) {
          // Ban expired, remove entry
          this.usersMap.delete(userKey);
          userData = undefined;
          if (this.config.enableLogging) {
            console.log(`[DDOS] Ban expired: ${ipAddress}`);
          }
        } else {
          // Still banned
          const remaining = userData.banExpiry ? Math.ceil((userData.banExpiry - now) / 1000) : 0;
          if (this.config.enableLogging) {
            console.log(`[DDOS] Blocked banned user: ${ipAddress} (${remaining}s remaining)`);
          }
          
          return {
            blocked: true,
            reason: 'USER_BANNED',
            message: {
              WARNING: 'You have been temporarily banned for sending too many requests',
              'Remaining Ban Time': `${remaining} seconds`,
              'Support Mail': this.config.supportMail,
              info: this.config.mainInfo
            }
          };
        }
      }

      // Initialize or update user data
      if (!userData) {
        userData = {
          count: 1,
          firstRequest: now,
          banned: false
        };
        this.usersMap.set(userKey, userData);
      } else {
        // Check if we're within the time window
        if ((now - userData.firstRequest) <= this.config.userDataTimeout) {
          userData.count++;
        } else {
          // Reset window
          userData.count = 1;
          userData.firstRequest = now;
        }
      }

      // Check if user exceeded rate limit
      if (userData.count > this.config.maxRequestsPerUser) {
        // Ban the user
        userData.banned = true;
        userData.banExpiry = now + this.config.userBanTimeout;
        
        if (this.config.enableLogging) {
          console.log(`[DDOS] User banned: ${ipAddress} (${userData.count} requests in ${Math.ceil((now - userData.firstRequest) / 1000)}s)`);
        }
        
        return {
          blocked: true,
          reason: 'RATE_LIMIT_EXCEEDED',
          message: {
            WARNING: 'Rate limit exceeded - You have been temporarily banned',
            'Requests Made': userData.count,
            'Ban Duration': `${Math.ceil(this.config.userBanTimeout / 1000)} seconds`,
            'Support Mail': this.config.supportMail,
            info: this.config.mainInfo
          }
        };
      }

      // Check for foreign country requests during normal operation
      if (geo !== this.config.mainCountry) {
        if (this.isDDoSAttack) {
          return {
            blocked: true,
            reason: 'GLOBAL_DDOS',
            message: {
              WARNING: 'Global DDOS Detected',
              Mail: this.config.supportMail
            }
          };
        }
        this.ddosCount += 1;
      }

      if (this.config.enableLogging) {
        const windowTime = Math.ceil((now - userData.firstRequest) / 1000);
        console.log(`[DDOS-LOG] Request from ${geo} (${ipAddress}) | Count: ${userData.count}/${this.config.maxRequestsPerUser} in ${windowTime}s | Global-DOS: ${this.ddosCount}/${this.config.ddosThreshold}`);
      }

      return { blocked: false };
    } catch (error) {
      console.error('[DDOS] Error in protection check:', error);
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

  // Method to get current user stats (for debugging)
  getUserStats(): { [key: string]: any } {
    const stats: { [key: string]: any } = {};
    for (const [key, userData] of this.usersMap.entries()) {
      stats[key] = {
        count: userData.count,
        banned: userData.banned,
        windowAge: userData.firstRequest ? Math.ceil((Date.now() - userData.firstRequest) / 1000) : 0,
        banTimeRemaining: userData.banExpiry ? Math.max(0, Math.ceil((userData.banExpiry - Date.now()) / 1000)) : 0
      };
    }
    return stats;
  }
}

export default DDoSProtection;