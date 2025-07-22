const crypto = require('crypto');
const jwt = require('jsonwebtoken');

/**
 * SecurityGuard - Camada de proteção para APIs Newcon
 * Implementa autenticação, rate limiting e auditoria
 */
class SecurityGuard {
    constructor(options = {}) {
        this.jwtSecret = options.jwtSecret || process.env.JWT_SECRET || 'newcon-triangulo-secret-key';
        this.rateLimitWindow = options.rateLimitWindow || 60000; // 1 minuto
        this.maxRequests = options.maxRequests || 10; // máximo por minuto
        this.requestHistory = new Map();
        this.auditLog = [];
    }

    /**
     * Gera token JWT para sessão segura
     * @param {Object} payload - Dados do usuário
     * @returns {Object} Token e refresh token
     */
    generateTokens(payload) {
        const accessToken = jwt.sign(
            { 
                ...payload,
                type: 'access',
                timestamp: Date.now()
            },
            this.jwtSecret,
            { expiresIn: '1h' }
        );

        const refreshToken = jwt.sign(
            { 
                userId: payload.userId,
                type: 'refresh',
                timestamp: Date.now()
            },
            this.jwtSecret,
            { expiresIn: '7d' }
        );

        return { accessToken, refreshToken };
    }
}