import { Injectable } from '@nestjs/common';
import { ConflictException, NotFoundException, UnauthorizedException } from '@nestjs/common/exceptions'
import * as bcrypt from 'bcrypt'
import { SignupDto } from './dto/signupDto';
import { PrismaService } from 'src/prisma/prisma.service';
import { MailerService } from 'src/mailer/mailer.service';
import { SigninDto } from './dto/signinDto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {

    constructor(
        private readonly prismaService: PrismaService,
        private readonly mailerService: MailerService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService
    ) { }


    async signup(signupDto: SignupDto) {
        //Vérifier si l'utilisateur est déjà inscrit
        const { email, username, password } = signupDto;

        const user = await this.prismaService.user.findUnique({ where: { email } })
        if (user) throw new ConflictException('User already exists');
        // Hasher le mot de passe
        const hash = await bcrypt.hash(password, 10)
        //Enregister l'utilisateur dans la base de données
        await this.prismaService.user.create({
            data: { email, username, password: hash },
        })
        // Envoyer un email de confirmation
        await this.mailerService.sendSignupConfirmation(email);
        return { data: 'User succesfully created' };
    }

    async signin(signinDto: SigninDto) {
        // Vérifier si l'utilisateur est déjà inscrit
        const { email, password } = signinDto;

        const user = await this.prismaService.user.findUnique({ where: { email } })
        if (!user) throw new NotFoundException("User not found");

        const match = await bcrypt.compare(password, user.password)
        if (!match) throw new UnauthorizedException("Password does not match")

        // Retourner un token jwt
        const payload = {
            sub: user.userId,
            email: user.email
        }

        const token = this.jwtService.sign(payload, {
            expiresIn: "2h", secret: this.configService.get("SECRET_KEY"),
        });

        return {
            token, uesr: {
                username: user.username,
                email: user.email
            }
        }
    }

}
