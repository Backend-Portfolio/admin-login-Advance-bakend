import { Body, Controller, Post, Req } from '@nestjs/common';
import { TotpService } from './totp.service';
import { AuthService } from './auth.service';
import type { Request } from 'express'

@Controller('auth')
export class AuthController {
    constructor(
        private totpService: TotpService,
        private authService: AuthService,
    ) { }

    @Post('verify-otp')
    async verifyOtp(@Body() body: { adminId: number; otp: string },
        @Req() req: Request) {
        return this.authService.verifyOtpAndLogin(
            body.adminId,
            body.otp,
            req
        )

    }


}
