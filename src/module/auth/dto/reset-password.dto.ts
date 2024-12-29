import { IsNotEmpty, IsString, Matches } from 'class-validator';

export class ResetPasswordDto {
    @IsNotEmpty()
    resetToken: string;

    @IsNotEmpty()
    @IsString()
    @Matches(
        /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/,
        { message: 'Password must be at least 6 characters long, include one letter, one number, and one special character.' }
    )
    newPassword: string;

    @IsNotEmpty()
    confirmPassword: string; 
}
