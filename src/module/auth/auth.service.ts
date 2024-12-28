import { Injectable, BadRequestException, UnauthorizedException, } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { ResetToken } from './entities/reset-token.entity';
import { LoginUserDto } from './dto/login-user.dto';
import { SignupUserDto } from './dto/create-user.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { MailService } from '../service/mail.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(ResetToken)
    private readonly resetTokenRepository: Repository<ResetToken>,
    private jwtService: JwtService,
    private readonly mailService: MailService,
  ) { }

  // For Signup user..............................................................................................................
  async signup(signupUserDto: SignupUserDto): Promise<Partial<User>> {
    const {
      email,
      password,
      confirmPassword,
      firstName,
      lastName,
      phoneNumber,
    } = signupUserDto;

    // Check if the user already exists
    const existingUser = await this.userRepository.findOne({
      where: { email },
    });
    if (existingUser) {
      throw new BadRequestException('User with this email already exists.');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if passwords match
    if (password !== confirmPassword) {
      throw new BadRequestException(
        'Password and Confirm Password do not match.',
      );
    }

    // Create a new user
    const newUser = this.userRepository.create({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      phoneNumber,
    });

    // Save the user to the database
    const savedUser = await this.userRepository.save(newUser);

    // Return only public fields
    return {
      id: savedUser.id,
      email: savedUser.email,
      firstName: savedUser.firstName,
      lastName: savedUser.lastName,
      phoneNumber: savedUser.phoneNumber,
      createdAt: savedUser.createdAt,
    };
  }

  // For login user...............................................................................................................
  async login({ email, password }: LoginUserDto): Promise<LoginResponseDto> {
    const user = await this.userRepository.findOne({
      where: { email },
      select: [
        'id',
        'email',
        'password',
        'firstName',
        'lastName',
        'phoneNumber',
        'createdAt',
      ],
    });
    if (!user) {
      throw new UnauthorizedException('Invalid email or password.');
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    // Generate JWT token for the user
    const token = await this.generateuserToken(user.id);

    // Store the refresh token in the database
    await this.storeRefreshToken(token.refreshToken, user);

    // Return user details, excluding the password
    const { password: _, ...userWithoutPassword } = user;
    return {
      ...userWithoutPassword,
      accessToken: token.accessToken,
      refreshToken: token.refreshToken,
    };
  }

  // For Refresh Token.............................................................................................................
  // For RefreshToken wich check from the data base it login expired or not & and valid user or not
  async refreshTokens(refreshToken: string) {
    const token = await this.refreshTokenRepository.findOne({
      where: { token: refreshToken },
      relations: ['user'],
    });

    // Validate if the token exists in the database
    if (!token) {
      throw new UnauthorizedException('Invalid refresh token.');
    }

    // Check if the token is expired
    if (new Date() > token.expiryDate) {
      throw new UnauthorizedException(
        'Refresh token has expired. Please log in again.',
      );
    }

    // Generate new token for the user
    const newToken = await this.generateuserToken(token.user.id);

    // Store the new refresh token in the database
    await this.storeRefreshToken(newToken.refreshToken, token.user);

    // Delete the previous refresh token from the database
    await this.refreshTokenRepository.delete({ token: refreshToken });

    return {
      accessToken: newToken.accessToken,
      refreshToken: newToken.refreshToken,
    };
  }

  // For Change Password............................................................................................................
  async updatePassword(userId: number, oldPassword: string, newPassword: string) {
    // Find the user by ID and select the password
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'password'],
    });

    if (!user) {
      throw new UnauthorizedException('User not found.');
    }

    // Check if the old password matches the current password
    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid) {
      throw new BadRequestException('Old password is incorrect.');
    }

    // Check if the new password is the same as the old password
    const isSameAsOldPassword = await bcrypt.compare(newPassword, user.password);
    if (isSameAsOldPassword) {
      throw new BadRequestException(
        'New password cannot be the same as the old password.',
      );
    }

    // Hash the new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password
    user.password = hashedNewPassword;
    await this.userRepository.save(user);

    return
  }

  // For Forget password............................................................................................................
  async forgotPassword(email: string,) {
    const user = await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email',]
    });

    // Set the expiration date
    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + 1);

    // User validation Check
    // if (!user) {
    //   throw new UnauthorizedException('Invalid email or User Not exist');
    // }

    // Save The New Generate Reset Token in DB
    if (user) {
      const resetToken = nanoid(64);
      // Create a new reset token record in the database and set the expiration date
      const newResetToken = this.resetTokenRepository.create({ token: resetToken, user, expiryDate });
      // Remove the existing refresh token for the user if it exists
      const existingToken = await this.resetTokenRepository.findOne({ where: { user } });
      if (existingToken) {
        await this.resetTokenRepository.delete({ id: existingToken.id });
      }
      // Save the new reset token in the database with the expiration date and user reference
      await this.resetTokenRepository.save(newResetToken);

      // Construct the reset password link
      const resetPasswordUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

      // Send the reset password email
      const subject = "Password Reset Request";
      const html = `
      <p>Hello,</p>
      <p>We received a request to reset your password. Please use the link below to set a new password:</p>
      <a href="${resetPasswordUrl}">Reset Password</a>
      <p>This link will expire in 1 hour.</p>
      <p>If you did not request a password reset, please ignore this email.</p>
    `;
      await this.mailService.sendMail(user.email, subject, html);

    }
    return { messaage: 'If this User exists, they will recive an email' }

  }

  // this funtion For  generate Access token and refresh Token......................................................................
  async generateuserToken(userId: number) {
    const accessToken = this.jwtService.sign({ userId });
    const refreshToken = uuidv4();
    return {
      accessToken,
      refreshToken,
    };
  }

  // For Function Calculate expiration date and store the all refreshToken Data in databases........................................
  async storeRefreshToken(token: string, user: User) {
    // Remove the existing refresh token for the user if it exists
    // const existingToken = await this.refreshTokenRepository.findOne({
    //   where: { user: { id: user.id } },
    // });

    // if (existingToken) {
    //   await this.refreshTokenRepository.delete({ id: existingToken.id });
    // }

    // Remove the existing refresh token for the user if it exists
    await this.refreshTokenRepository.delete({ user: { id: user.id } });

    // Calculate the expiration date for the new refresh token
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 7);

    // Create a new refresh token entity
    const newRefreshToken = this.refreshTokenRepository.create({
      token,
      user,
      expiryDate,
    });

    // Save the new refresh token in the database
    await this.refreshTokenRepository.save(newRefreshToken);
  }
}
