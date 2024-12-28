import {
  Controller,
  Body,
  Post,
  HttpCode,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
  Put,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { AuthGuard } from '../guards/auth.guard';
import { ForgotpasswordDto } from './dto/forgot-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  // POST: Signup
  @Post('signup') //auth/signup
  @HttpCode(201) // Explicitly set the response
  async signup(@Body() body: SignupUserDto) {
    try {
      const user = await this.authService.signup(body);
      return {
        status: 'success',
        message: 'User signed up successfully',
        data: user,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error; // return 401 Unauthorized
      }
      throw new BadRequestException(error.message || 'Signup failed.'); //  return 400 Bad Request for other errors
    }
  }

  // POST: Login
  @Post('login') //auth/login
  @HttpCode(200) // Explicitly set the response
  async login(@Body() loginUserDto: LoginUserDto) {
    try {
      const user = await this.authService.login(loginUserDto);
      return {
        status: 'success',
        message: 'User logged in successfully',
        data: user,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error; //  return 401 Unauthorized
      }
      throw new BadRequestException(error.message || 'Login failed.'); // 400 Bad Request for other errors
    }
  }

  // POST: Refresh Token
  @Post('refresh') //auth/refresh
  @HttpCode(201) // Explicitly set the response
  async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    try {
      const tokens = await this.authService.refreshTokens(
        refreshTokenDto.refreshToken,
      );
      return {
        status: 'success',
        message: 'Tokens refreshed successfully',
        data: tokens,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error; // return 401 Unauthorized
      } else if (error instanceof BadRequestException) {
        throw error; // return 400 Bad Request
      }
      throw new InternalServerErrorException(
        'An unexpected error occurred while refreshing tokens.',
      );
    }
  }

  // POST: Change Password
  @UseGuards(AuthGuard)
  @Put('update-password') // auth/update-password
  @HttpCode(201)
  async updatePassword(@Body() changePasswordDto: ChangePasswordDto, @Request() req) {
    try {
      const userId = req.user?.userId; // Extract user ID from the token payload
      if (!userId) {
        throw new UnauthorizedException('User not found in request.');
      }
      await this.authService.updatePassword(
        userId,
        changePasswordDto.oldPassword,
        changePasswordDto.newPassword,
      );

      return {
        status: 'success',
        message: 'Password updated successfully',
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error; // 401 Unauthorized
      } else if (error instanceof BadRequestException) {
        throw error; // 400 Bad Request
      } else {
        throw new InternalServerErrorException(
          'An unexpected error occurred while updating the password.',
        );
      }
    }
  }

  // POST: Forgot Password
  @Post('forgot-password') //auth/forgot-password
  @HttpCode(201) // Explicitly set the response
  async forgotPassword(@Body() forgotpasswordDto: ForgotpasswordDto) {
    return this.authService.forgotPassword(forgotpasswordDto.email)
  }


}
