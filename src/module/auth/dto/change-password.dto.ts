import { IsNotEmpty, Matches } from 'class-validator';

export class ChangePasswordDto {
  @IsNotEmpty()
  oldPassword: string;

  @IsNotEmpty()
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, {
    message:
      'Password must be at least 8 characters long, include one letter, one number, and one special character.',
  })
  newPassword: string;
}
