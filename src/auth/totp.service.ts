import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';
import { Injectable } from '@nestjs/common';

export interface TotpSecret {
  ascii: string;
  hex: string;
  base32: string;
  otpauth_url: string;
}

@Injectable()
export class TotpService {
  /**
   * Generates a TOTP secret for a given email
   * @param email - User email
   * @returns TotpSecret object containing base32, hex, ascii, otpauth_url
   */

  generateSecret(email: string): TotpSecret {
    const secret = speakeasy.generateSecret({
      name: `MyPortfolio (${email})`, // secret.base32
      length: 20,
    });
    return secret;
  }

  /**
   * Generates a QR code data URL from a secret
   * @param secret - Base32 secret string
   * @returns Promise<string> - QR code as Data URL
   */

  async generateQr(secret: string): Promise<string> {
    return await qrcode.toDataURL(secret);
  }

  /** Verifies a TOTP token against a secret
   * @param secret - Base32 secret string
   * @param token - TOTP token from user
   * @returns boolean - true if valid
   */
  verifyToken(secret: string, token: string): boolean {
    return speakeasy.totp.verifyToken({
      secret,
      encoding: 'base32',
      token,
      window: 1,
    });
  }
}
