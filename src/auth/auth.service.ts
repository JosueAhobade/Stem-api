import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(private userService  : UsersService, private jwtService : JwtService ){ }

    async login(data : AuthDto) : Promise<any>{
        const user = await this.userService.findByUsername(data.username)
        if(!user ||  !await bcrypt.compare(data.password, user.password))
            throw new UnauthorizedException
        const payload = { id : user.id, username : user.username}

        return {
            access_token : await this.jwtService.signAsync(payload,{secret : process.env.JWT_SECRET}),
            user : user
        }
    }

}
