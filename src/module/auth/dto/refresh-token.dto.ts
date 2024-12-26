import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class RefreshTokenDto {
    @IsNotEmpty()
    @IsUUID()
    refreshToken: string;

    //   @IsNotEmpty()
    //   @IsString()
    //   userId: number;
}
