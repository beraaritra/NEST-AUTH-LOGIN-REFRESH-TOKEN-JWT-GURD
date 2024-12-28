import { Injectable } from "@nestjs/common";
import * as nodemailer from "nodemailer";

@Injectable()
export class MailService {
    private transporter: nodemailer.Transporter;

    constructor() {
        // Initialize the Nodemailer transporter with SMTP configuration
        this.transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST, // e.g., "smtp.gmail.com"
            port: Number(process.env.SMTP_PORT) || 587, // Default SMTP port
            secure: false, // Use SSL/TLS
            auth: {
                user: process.env.SMTP_USER, // SMTP username (e.g., email address)
                pass: process.env.SMTP_PASSWORD, // SMTP password
            },
        });
    }

    async sendMail(to: string, subject: string, html: string): Promise<void> {
        try {
            await this.transporter.sendMail({
                from: process.env.SMTP_FROM || '"Support" <support@example.com>', // Sender name and email
                to,
                subject,
                html, // Email body in HTML format
            });
            console.log("Email sent successfully.");
        } catch (error) {
            console.error("Failed to send email:", error);
            throw new Error("Failed to send email");
        }
    }
}
