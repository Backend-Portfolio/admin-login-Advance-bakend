import { Module } from '@nestjs/common';
import {AuthController} from "./auth.controller"
import {AuthService} from "./auth.service"
import {TotpService} from "./totp.service"
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [AuthController],
  providers: [AuthService,TotpService],
  exports:[AuthService]
})
export class AuthModule {}
