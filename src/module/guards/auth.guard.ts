import { JwtService } from '@nestjs/jwt';
import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common';
import { Observable } from 'rxjs';
import { Request } from 'express';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(private jwtService: JwtService) { }

    canActivate(
        context: ExecutionContext
    ): boolean | Promise<boolean> | Observable<boolean> {
        const request: Request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);

        if (!token) {
            throw new UnauthorizedException('Token not provided or invalid');
        }

        try {
            // Verify the token using JwtService
            const payload = this.jwtService.verify(token);
            // Optionally, attach the payload to the request object for later use
            (request as any).userId = payload.userId;
        } catch (e) {
            Logger.error('Invalid token', e.stack);
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