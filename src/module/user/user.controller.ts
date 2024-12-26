import { Controller, Get, Param, UseGuards, Request, Body, BadRequestException, Patch } from '@nestjs/common';
import { UserService } from './user.service';
import { AuthGuard } from '../guards/auth.guard'; // Import the AuthGuard

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) { }

  // GET: /users/profile (protected route)
  @UseGuards(AuthGuard) // Protect this route with AuthGuard
  @Get('profile')
  async getProfile(@Request() req) {
    const userId = req.userId; // Get userId from request (set in AuthGuard)
    const user = await this.userService.findUserById(userId);
    return { status: 'success', message: 'profile get successfully By JWT', data: user };
  }

  // GET: /users/:id (public route to get user data by ID)
  @Get(':id')
  async getUserById(@Param('id') id: number) {
    const user = await this.userService.findUserById(id);
    return { status: 'success', message: 'profile get successfully By User ID', data: user };
  }

}
