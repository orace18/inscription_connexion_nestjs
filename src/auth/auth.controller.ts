import { Body, Controller, Post } from '@nestjs/common';
import { SignupDto } from './dto/signupDto';
import { AuthService } from './auth.service';
import { SigninDto } from './dto/signinDto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService){}

    @Post("signup")
    signup(@Body() signupDto: SignupDto){
        return this.authService.signup(signupDto)
    }

    @Post("signin")
    signin(@Body() signinDto: SigninDto){
        return this.authService.signin(signinDto)
    }
}
