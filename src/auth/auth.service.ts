import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { TotpService } from './totp.service';
import { Request } from 'express';
import { AuthProvider } from '../../generated/prisma/enums';
import * as bcrypt from 'bcrypt';
import { addDays } from 'date-fns';
import * as jwt from 'jsonwebtoken';

type TUser = {
  email: string;
  provider: AuthProvider;
  providerId: string;
};

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private totpService: TotpService,
  ) {}

  // OAuth Login (Google/GitHub)
  async oauthLogin(user: TUser, req?: Request) {
    // find admin by email
    let admin = await this.prisma.admin.findUnique({
      where: { email: user.email },
    });

    // first time or OTP not enabled => generate TOTP

    if (!admin || !admin?.otpEnabled) {
      const secret = this.totpService.generateSecret(user.email).base32;

      admin = await this.prisma.admin.upsert({
        where: { email: user.email },
        update: { otpSecret: secret, otpEnabled: true },
        create: {
          email: user.email,
          provider: user.provider,
          providerId: user.providerId,
          otpSecret: secret,
          otpEnabled: true,
          role: 'ADMIN',
        },
      });
    }

    if (!admin.otpSecret) throw new UnauthorizedException('error');
    // Generate QR for first-time OTP setup
    const qr = await this.totpService.generateQr(admin.otpSecret);

    // Create session + tokens if OTP is already verified
    // (For first-time, frontend shows QR and requests OTP verification)
    const tokens = await this.createSessionTokens(admin.id, req);

    // Log the login attempt
    await this.audit(admin.id, 'OAuth_LOGIN', req?.ip || 'unknown');
  }

  // Session + JWT Tokens
  async createSessionTokens(adminId: number, req?: Request) {
    // Generate refresh token
    const refreshTokenRaw = Math.random().toString(36).substring(2, 15);
    const refreshHash = await bcrypt.hash(refreshTokenRaw, 10);

    // Save session in DB
    const session = await this.prisma.session.create({
      data: {
        adminId,
        refreshHash,
        userAgent: req?.headers['user-agent'] || 'unknown',
        ip: req?.ip || 'unknown',
        expiresAt: addDays(new Date(), 7),
      },
    });

    if (!process.env.ACCESS_TOKEN_SECRET)
      throw new Error(' Access Token error');

    // Generate JWT tokens
    const accessToken = jwt.sign(
      { sub: adminId, sid: session.id },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '15m' },
    );

    if (!process.env.REFRESH_TOKEN_SECRET)
      throw new Error('refresh token error');
    const refreshToken = jwt.sign(
      { sub: adminId, sid: session.id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' },
    );

    return { accessToken, refreshToken, sessionId: session.id };
  }

  // Audit Logging
  async audit(adminId: number, action: string, ip: string, target?: string) {
    return this.prisma.auditLog.create({
      data: { adminId, action, target, ip },
    });
  }

  // Find Admin by ID
  async findAdminById(adminId: number) {
    const admin = await this.prisma.admin.findUnique({
      where: { id: adminId },
    });
    if (!admin) throw new UnauthorizedException('admin not found!');
    return admin;
  }

  async verifyOtpAndLogin(adminId:number,otp:string,req:Request){

    // Find Admin
    const admin = await this.prisma.admin.findUnique({where: {id: adminId}})

    if(!admin || !admin.otpSecret){
        throw new UnauthorizedException('admin not Found');
    }

    const isValid = this.totpService.verifyToken(admin.otpSecret,otp)

    if(!isValid){
        throw new UnauthorizedException('Invalid OTP')
    }

    const tokens = await this.createSessionTokens(
        adminId,
        req
    )

    await this.audit(admin.id,'OTP_VERIFIED_LOGIN', req.ip || 'unknown')

    return {
        message : 'login successful',
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken
    }

  }

}
