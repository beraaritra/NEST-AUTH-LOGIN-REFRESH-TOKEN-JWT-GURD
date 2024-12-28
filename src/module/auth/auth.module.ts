import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../user/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ResetToken } from './entities/reset-token.entity';
import { MailModule } from '../service/mail.module';

@Module({
  imports: [TypeOrmModule.forFeature([User, RefreshToken, ResetToken]),
    MailModule,
  JwtModule.registerAsync({
    imports: [ConfigModule],
    inject: [ConfigService],
    useFactory: async (configService: ConfigService) => ({
      secret: configService.get<string>('JWT_SECRET'),
      signOptions: { expiresIn: configService.get<string>('JWT_EXPIRES_IN') },
    }),
  })
  ],

  exports: [AuthService, JwtModule],
  providers: [AuthService],
  controllers: [AuthController],
})
export class AuthModule { }
