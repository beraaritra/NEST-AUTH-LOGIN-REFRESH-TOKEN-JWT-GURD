import { Injectable, BadRequestException, UnauthorizedException, } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { ResetToken } from './entities/reset-token.entity';
import { LoginUserDto } from './dto/login-user.dto';
import { SignupUserDto } from './dto/create-user.dto';
// import { LoginResponseDto } from './dto/login-response.dto';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { MailService } from '../service/mail.service';
import { VerifyToken } from './entities/verify-token.entity';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(ResetToken)
    private readonly resetTokenRepository: Repository<ResetToken>,
    @InjectRepository(VerifyToken)
    private readonly verifyTokenRepository: Repository<VerifyToken>,
    private jwtService: JwtService,
    private readonly mailService: MailService,
  ) { }

  // For Signup user..............................................................................................................
  async signup(signupUserDto: SignupUserDto): Promise<Partial<User>> {
    const { email, password, confirmPassword, firstName, lastName, phoneNumber } = signupUserDto;

    const existingUser = await this.userRepository.findOne({ where: { email } });
    if (existingUser) throw new BadRequestException('User with this email already exists.');

    if (password !== confirmPassword) throw new BadRequestException('Passwords do not match.');

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = this.userRepository.create({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      phoneNumber,
      verifiedUser: false,
    });

    const savedUser = await this.userRepository.save(newUser);

    // Generate 6-digit code and save to verify-token.entity
    const code = Math.floor(100000 + Math.random() * 900000).toString(); // Random 6-digit code
    const expiryDate = new Date(Date.now() + 10 * 60 * 1000); // 10-minute expiry

    const verifyToken = this.verifyTokenRepository.create({
      code,
      user: savedUser,
      expiryDate,
    });
    await this.verifyTokenRepository.save(verifyToken);

    // Send email with the verification code
    const emailBody =
      `<p>Hi ${firstName},</p>
        <p>Your verification code is: <b>${code}</b>.</p>
        <p>This code is valid for 10 minutes.</p>`;
    await this.mailService.sendMail(email, 'Verify Your Email', emailBody);

    // Generate tokens
    const tokens = await this.generateuserToken(savedUser.id);
    await this.storeRefreshToken(tokens.refreshToken, savedUser);

    // Return response (exclude password)
    return {
      id: savedUser.id,
      email: savedUser.email,
      firstName: savedUser.firstName,
      lastName: savedUser.lastName,
      phoneNumber: savedUser.phoneNumber,
      verifiedUser: savedUser.verifiedUser,
      ...tokens
    };
  }

  // For verify Email Address ....................................................................................................
  async verifyEmail(email: string, code: string): Promise<{ email: string }> {

    // Find the user by email
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('Invaalid token not found.');
    }

    // Find the verification token for the user
    const verifyToken = await this.verifyTokenRepository.findOne({
      where: { user: { id: user.id }, code },
    });

    if (!verifyToken) {
      throw new BadRequestException('Invalid verification code.');
    }

    // Check if the token has expired
    if (new Date() > verifyToken.expiryDate) {
      throw new BadRequestException('Verification code has expired.');
    }

    // Mark user as verified
    user.verifiedUser = true;
    await this.userRepository.save(user);

    // Send a welcome email
    const welcomeEmailBody = `<p>Welcome to our platform, ${user.firstName}!</p>`;
    await this.mailService.sendMail(user.email, 'Welcome!', welcomeEmailBody);

    // Delete the verification token
    await this.verifyTokenRepository.delete({ id: verifyToken.id });

    return { email: user.email };
  }

  // For login user...............................................................................................................
  async login({ email, password }: LoginUserDto) {
    const user = await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email', 'password', 'verifiedUser'],
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    if (!user.verifiedUser) {
      throw new UnauthorizedException('Email is not verified.');
    }

    const tokens = await this.generateuserToken(user.id);
    await this.storeRefreshToken(tokens.refreshToken, user);

    return {
      userId: user.id,
      ...tokens,
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
  async updatePassword(userId: number, newPassword: string, confirmPassword: string) {
    // Find the user by ID and select the password
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'password'],
    });

    if (!user) {
      throw new UnauthorizedException('User not found.');
    }

    // Verify if the passwords match
    if (newPassword !== confirmPassword) {
      throw new BadRequestException('New password and confirm password do not match.');
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password
    user.password = hashedPassword;
    await this.userRepository.save(user);

  }

  // For Forget password Link generate...............................................................................................
  async forgotPassword(email: string,) {
    const user = await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email',]
    });

    // Set the expiration date
    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + 1);

    // User validation Check
    if (!user) {
      throw new UnauthorizedException('Invalid email or User Not exist');
    }

    // Save The New Generate Reset Token in DB
    else {
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

  }

  // For Reset Password using Forgot Password Link ..................................................................................
  async resetPassword(resetToken: string, newPassword: string, confirmPassword: string) {
    // Validate the reset token
    const token = await this.resetTokenRepository.findOne({
      where: { token: resetToken },
      relations: ['user'],
    });

    if (!token) {
      throw new UnauthorizedException('Invalid reset password Link.');
    }

    // Check if the token has expired
    if (new Date() > token.expiryDate) {
      await this.resetTokenRepository.delete({ id: token.id }); // Clean up expired token
      throw new UnauthorizedException('Reset token has expired.');
    }

    const user = token.user;

    // Verify if the passwords match
    if (newPassword !== confirmPassword) {
      throw new BadRequestException('New password and confirm password do not match.');
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    //  Update the user's password in the database
    user.password = hashedPassword;
    await this.userRepository.save(user);

    //  Delete the used reset token
    await this.resetTokenRepository.delete({ id: token.id });

    // Send a success email to the user
    const subject = "Password Reset Successful";
    const html = `
      <p>Hello ${user.firstName},</p>
      <p>Your password has been reset successfully. If you did not perform this action, please contact support immediately.</p>
      <p>Thank you,</p>
      <p>The Team</p>
    `;
    await this.mailService.sendMail(user.email, subject, html);
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
