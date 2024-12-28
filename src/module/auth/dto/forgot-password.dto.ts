import { IsNotEmpty } from 'class-validator';

export class ForgotpasswordDto {
    @IsNotEmpty()
    email: string;
}
