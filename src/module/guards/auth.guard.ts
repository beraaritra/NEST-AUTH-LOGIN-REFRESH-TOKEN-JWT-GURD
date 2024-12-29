import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) { }

  canActivate(context: ExecutionContext): boolean {
    const request: Request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Token not provided or invalid');
    }

    try {
      // Verify the token using JwtService
      const payload = this.jwtService.verify(token);

      // Attach user details to the request object
      request.user = { userId: payload.userId, email: payload.email }; 
      Logger.log(`JWT User: ${JSON.stringify(request.user)}`);
    } catch (error) {
      Logger.error('Invalid token', error.stack);
      throw new UnauthorizedException('Invalid token.');
    }

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const authHeader = request.headers.authorization;
    if (!authHeader) return undefined;
    return authHeader.split(' ')[1]; // Extract the token after 'Bearer '
  }
}
