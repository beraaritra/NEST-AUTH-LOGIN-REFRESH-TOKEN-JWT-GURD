import { Column, CreateDateColumn, Entity, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { User } from '../../user/entities/user.entity';

@Entity()
export class ResetToken {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    token: string;

    @ManyToOne(() => User, (user) => user.resetTokens, { onDelete: 'CASCADE' })
    user: User;

    @Column()
    expiryDate: Date;

    @CreateDateColumn()
    createdAt: Date;
}
