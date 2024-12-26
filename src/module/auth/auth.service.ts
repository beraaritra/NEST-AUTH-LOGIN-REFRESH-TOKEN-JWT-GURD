import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { LoginUserDto } from './dto/login-user.dto';
import { SignupUserDto } from './dto/create-user.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        @InjectRepository(RefreshToken)
        private readonly refreshTokenRepository: Repository<RefreshToken>,
        private jwtService: JwtService,
    ) { }

    // For signup user........................................................................................
    async signup(signupUserDto: SignupUserDto): Promise<Partial<User>> {
        const { email, password, confirmPassword, firstName, lastName, phoneNumber } = signupUserDto;

        // Check if the user already exists
        const existingUser = await this.userRepository.findOne({ where: { email } });
        if (existingUser) {
            throw new BadRequestException('User with this email already exists.');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Check if passwords match
        if (password !== confirmPassword) {
            throw new BadRequestException('Password and Confirm Password do not match.');
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

    // For login user.........................................................................................
    async login({ email, password }: LoginUserDto): Promise<LoginResponseDto> {
        const user = await this.userRepository.findOne({
            where: { email },
            select: ['id', 'email', 'password', 'firstName', 'lastName', 'phoneNumber', 'createdAt']
        })
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
        await this.storeRefreshToken(token.refreshToken, user.id);

        // Return user details, excluding the password
        const { password: _, ...userWithoutPassword } = user;
        return {
            ...userWithoutPassword,
            accessToken: token.accessToken,
            refreshToken: token.refreshToken,
        };
    }

    // For Refresh Token...........................................................................................................
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
            throw new UnauthorizedException('Refresh token has expired. Please log in again.');
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

    // this funtion For  generate Access token and refresh Token...................................................................
    async generateuserToken(userId: number) {
        const accessToken = this.jwtService.sign({ userId });
        const refreshToken = uuidv4()
        return {
            accessToken,
            refreshToken
        }
    }

    // For Function Calculate expiration date and store the all refreshToken Data in databases.....................................
    async storeRefreshToken(token: string, user) {
        // Calculate expiration date
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 7);
        // expiryDate.setSeconds(expiryDate.getSeconds() + 10);

        const newRefreshToken = this.refreshTokenRepository.create({ token, user, expiryDate });
        await this.refreshTokenRepository.save(newRefreshToken);
    }
}
