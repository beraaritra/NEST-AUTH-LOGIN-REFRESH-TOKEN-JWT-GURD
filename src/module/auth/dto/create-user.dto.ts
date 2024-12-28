import { IsString, IsEmail, Matches, IsNotEmpty, MinLength } from 'class-validator';

export class SignupUserDto {
  @IsEmail({}, { message: 'Please provide a valid email address.' })
  email: string;

  @IsString()
  @IsNotEmpty()
  @Matches(
    /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/,
    { message: 'Password must be at least 6 characters long, include one letter, one number, and one special character.' }
  )
  password: string;

  @IsNotEmpty()
  @MinLength(6)
  confirmPassword: string;

  @IsString()
  firstName: string;

  @IsString()
  lastName: string;

  @IsString()
  phoneNumber: string;
}
