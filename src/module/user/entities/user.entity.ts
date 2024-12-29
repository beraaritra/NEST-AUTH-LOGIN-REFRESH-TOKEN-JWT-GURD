import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, OneToMany } from 'typeorm';
import { RefreshToken } from '../../auth/entities/refresh-token.entity';
import { ResetToken } from 'src/module/auth/entities/reset-token.entity';
import { VerifyToken } from 'src/module/auth/entities/verify-token.entity';

@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({ unique: true })
    email: string;

    @Column({ nullable: true, select: false })
    password: string;

    @Column({ nullable: true })
    firstName: string;

    @Column({ nullable: true })
    lastName: string;

    @Column({ nullable: true })
    phoneNumber: string;

    @Column({ default: false })
    verifiedUser: boolean;

    @CreateDateColumn()
    createdAt: Date;

    // Relationship with refresh tokens
    @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
    refreshTokens: RefreshToken[];

    // Relationship with reset tokens
    @OneToMany(() => ResetToken, (resetToken) => resetToken.user, { cascade: true })
    resetTokens: ResetToken[];

    // Relationship with verify tokens
    @OneToMany(() => VerifyToken, (verifyToken) => verifyToken.user, { cascade: true })
    verifyTokens: VerifyToken[];

}
