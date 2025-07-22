const crypto = require("crypto");
const jwt = require("jsonwebtoken");

/**
 * SecurityGuard - Camada de proteção para APIs Newcon
 * Implementa autenticação, rate limiting e auditoria
 */
class SecurityGuard {
  constructor(options = {}) {
    this.jwtSecret =
      options.jwtSecret ||
      process.env.JWT_SECRET ||
      "newcon-triangulo-secret-key";
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
        type: "access",
        timestamp: Date.now(),
      },
      this.jwtSecret,
      { expiresIn: "1h" }
    );

    const refreshToken = jwt.sign(
      {
        userId: payload.userId,
        type: "refresh",
        timestamp: Date.now(),
      },
      this.jwtSecret,
      { expiresIn: "7d" }
    );

    return { accessToken, refreshToken };
  }

  /**
   * Valida token JWT
   * @param {string} token - Token a ser validado
   * @returns {Object|null} Payload decodificado ou null se inválido
   */
  validateToken(token) {
    try {
      const decoded = jwt.verify(token, this.jwtSecret);

      // Verifica se é token de acesso
      if (decoded.type !== "access") {
        throw new Error("Invalid token type");
      }

      return decoded;
    } catch (error) {
      this.logSecurityEvent("TOKEN_VALIDATION_FAILED", {
        error: error.message,
      });
      return null;
    }
  }
  /**
   * Rate limiting - Controla frequência de requests
   * @param {string} identifier - IP ou userId
   * @returns {boolean} True se permitido, false se excedeu limite
   */
  checkRateLimit(identifier) {
    const now = Date.now();

    if (!this.requestHistory.has(identifier)) {
      this.requestHistory.set(identifier, []);
    }

    const userRequests = this.requestHistory.get(identifier);

    // Remove requests antigos (fora da janela)
    const validRequests = userRequests.filter(
      (timestamp) => now - timestamp < this.rateLimitWindow
    );

    // Atualiza histórico
    this.requestHistory.set(identifier, validRequests);

    // Verifica limite
    if (validRequests.length >= this.maxRequests) {
      this.logSecurityEvent("RATE_LIMIT_EXCEEDED", {
        identifier,
        requestCount: validRequests.length,
      });
      return false;
    }

    // Adiciona request atual
    validRequests.push(now);
    this.requestHistory.set(identifier, validRequests);

    return true;
  }
  /**
   * Sanitiza dados de entrada para prevenir ataques
   * @param {Object} data - Dados a serem sanitizados
   * @returns {Object} Dados sanitizados
   */
  sanitizeInput(data) {
    if (typeof data !== "object" || data === null) {
      return data;
    }

    const sanitized = {};

    for (const [key, value] of Object.entries(data)) {
      if (typeof value === "string") {
        // Remove caracteres perigosos
        sanitized[key] = value
          .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
          .replace(/javascript:/gi, "")
          .replace(/on\w+\s*=/gi, "")
          .trim()
          .substring(0, 1000); // Limita tamanho
      } else if (typeof value === "object") {
        sanitized[key] = this.sanitizeInput(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }
  /**
   * Valida CPF (específico para dados brasileiros)
   * @param {string} cpf - CPF a ser validado
   * @returns {boolean} True se válido
   */
  validateCPF(cpf) {
    // Remove formatação
    cpf = cpf.replace(/[^\d]/g, "");

    // Verifica se tem 11 dígitos
    if (cpf.length !== 11) return false;

    // Verifica se todos os dígitos são iguais
    if (/^(\d)\1{10}$/.test(cpf)) return false;

    // Calcula primeiro dígito verificador
    let sum = 0;
    for (let i = 0; i < 9; i++) {
      sum += parseInt(cpf[i]) * (10 - i);
    }
    let remainder = sum % 11;
    const digit1 = remainder < 2 ? 0 : 11 - remainder;

    if (parseInt(cpf[9]) !== digit1) return false;

    // Calcula segundo dígito verificador
    sum = 0;
    for (let i = 0; i < 10; i++) {
      sum += parseInt(cpf[i]) * (11 - i);
    }
    remainder = sum % 11;
    const digit2 = remainder < 2 ? 0 : 11 - remainder;

    return parseInt(cpf[10]) === digit2;
  }
  /**
   * Middleware Express para autenticação
   */
  authMiddleware() {
    return (req, res, next) => {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
          error: "UNAUTHORIZED",
          message: "Token de acesso obrigatório",
        });
      }

      const token = authHeader.substring(7);
      const decoded = this.validateToken(token);

      if (!decoded) {
        return res.status(401).json({
          error: "INVALID_TOKEN",
          message: "Token inválido ou expirado",
        });
      }

      req.user = decoded;
      next();
    };
  }
}
