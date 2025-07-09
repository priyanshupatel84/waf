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

class DDoSProtection {
  private userRecently = new Set<string>();
  private usersMap = new Map<string, number>();
  private ddosCount = 0;
  private isDDoSAttack = false;
  private config: DDoSProtectionConfig;

  constructor(config: DDoSProtectionConfig) {
    this.config = config;
    this.startDDoSMonitoring();
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
      const currentCount = this.usersMap.get(userKey) || 0;

      // Check if user is already banned
      if (currentCount > this.config.maxRequestsPerUser) {
        if (currentCount > 99) {
          return {
            blocked: true,
            reason: 'USER_DDOS',
            message: {
              WARNING: 'User DDOS Detected - Permanently Banned',
              'Support Mail': this.config.supportMail,
              info: this.config.mainInfo
            }
          };
        }

        if (!this.isDDoSAttack) {
          // Temporary ban
          setTimeout(() => {
            if (this.config.enableLogging) {
              console.log(`[DDOS] User Ban Deleted: ${ipAddress}`);
            }
            this.usersMap.set(userKey, 0);
          }, this.config.userBanTimeout);

          if (this.config.enableLogging) {
            console.log(`[DDOS] User Banned: ${ipAddress}`);
          }
          
          this.usersMap.set(userKey, currentCount + 999);
          return {
            blocked: true,
            reason: 'USER_DDOS',
            message: {
              WARNING: 'User DDOS Detected',
              'Support Mail': this.config.supportMail,
              info: this.config.mainInfo
            }
          };
        }

        // During global DDoS attack
        if (this.config.enableLogging) {
          console.log(`[DDOS] User Unlimited Banned: ${ipAddress}`);
        }
        
        this.usersMap.set(userKey, currentCount + 999);
        return {
          blocked: true,
          reason: 'USER_DDOS',
          message: {
            WARNING: 'User DDOS Detected',
            'Support Mail': this.config.supportMail,
            info: this.config.mainInfo
          }
        };
      }

      // Update user request count
      if (currentCount > 0) {
        this.usersMap.set(userKey, currentCount + 1);
      } else {
        // First request from this IP
        setTimeout(() => {
          if (this.config.enableLogging) {
            console.log(`[DDOS] User DATA Deleted: ${ipAddress}`);
          }
          this.usersMap.set(userKey, 0);
        }, this.config.userDataTimeout);
        
        this.usersMap.set(userKey, 1);
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
        console.log(`[DDOS-LOG] Joined site: ${geo} | DOS-Count: ${currentCount}/100 | Global-DOS: ${this.ddosCount}/200`);
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
}

export default DDoSProtection;