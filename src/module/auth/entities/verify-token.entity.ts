import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne, } from 'typeorm';
import { User } from '../../user/entities/user.entity';

@Entity('verify_tokens')
export class VerifyToken {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    code: string;

    @Column()
    expiryDate: Date;

    @CreateDateColumn()
    createdAt: Date;

    @ManyToOne(() => User, (user) => user.verifyTokens)
    user: User;
}