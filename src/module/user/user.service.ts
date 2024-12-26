import { BadRequestException, Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
    ) { }

    // Fetch user data by ID
    async findUserById(userId: number): Promise<User> {
        try {
            const user = await this.userRepository.findOne({
                where: { id: userId },
            });

            // If user not found, throw NotFoundException
            if (!user) {
                throw new NotFoundException(`User with ID ${userId} not found.`);
            }

            return user;
        } catch (error) {
            // Handle unexpected database or other internal errors
            if (error instanceof NotFoundException) {
                throw error;
            }
            throw new InternalServerErrorException('An error occurred while fetching the user data.');
        }
    }

}
