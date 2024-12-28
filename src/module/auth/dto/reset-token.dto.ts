import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class ResetTokenDto {
    @IsNotEmpty()
    @IsUUID()
    resetToken: string;

    //   @IsNotEmpty()
    //   @IsString()
    //   userId: number;
}
