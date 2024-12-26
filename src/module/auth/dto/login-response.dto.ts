export class LoginResponseDto {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  phoneNumber: string;
  createdAt: Date;
  accessToken: string;
  refreshToken: string;
}
