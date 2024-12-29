import { IsEmail, IsString, IsNotEmpty, Length } from 'class-validator';

export class VerifyEmailTokenDto {
    // @IsEmail()
    // email: string;

    @IsString()
    @IsNotEmpty()
    @Length(6, 6)
    code: string; // 6-digit code
}
