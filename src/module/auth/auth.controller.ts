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

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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
  @Put('change-password') //auth/change-password
  @HttpCode(200) // Explicitly set the response
  async changePassword(
    @Body() changePasswordDto: ChangePasswordDto,
    @Request() req,
  ) {
    const userId = req.user?.userId; // optional chaining to access id safely
    if (!userId) {
      throw new UnauthorizedException('User not found in request.');
    }
    return this.authService.changePassword(
      userId,
      changePasswordDto.oldPassword,
      changePasswordDto.newPassword,
    );
  }

  
}
