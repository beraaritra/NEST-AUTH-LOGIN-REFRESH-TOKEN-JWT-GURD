import { Module } from '@nestjs/common';
import { MailService } from './mail.service';

@Module({
    providers: [MailService],
    exports: [MailService], // Export it so it can be used in other modules
})
export class MailModule { }
