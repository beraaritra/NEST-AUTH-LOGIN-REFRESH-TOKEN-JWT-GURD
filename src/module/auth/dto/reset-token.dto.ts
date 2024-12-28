import { IsNotEmpty, IsUUID } from 'class-validator';

export class ResetTokenDto {
    @IsNotEmpty()
    @IsUUID()
    resetToken: string;
}
