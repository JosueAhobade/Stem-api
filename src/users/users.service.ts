import { Injectable , HttpException , HttpStatus } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './users.schema';
import { Model } from 'mongoose';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
    constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

    async create(createUserDto: CreateUserDto) {
        let user = await this.userModel.findOne({
          username: createUserDto.username,
        });

        if (user)
            throw new HttpException('Nom utilisateur déjà pris', HttpStatus.CONFLICT);

        user = await this.userModel.findOne({
            email: createUserDto.email,
         });

        if (user)
            throw new HttpException('Email déjà pris', HttpStatus.CONFLICT);
        
        return this.userModel.create({
            ...createUserDto,
            password: await bcrypt.hash(createUserDto.password, 10),
        });
    }

    async update(id: string, updateUserDto: UpdateUserDto) {
        try{
          const user = await this.userModel.findById(id)
          return this.userModel.findByIdAndUpdate(id, updateUserDto,{new:true,lean:true})
        }catch(error){
          throw  new HttpException("User not found", HttpStatus.NOT_FOUND)
        }
        
      }
      async findByUsername(username : string){
        return await this.userModel.findOne({
          username,
        });
    
      }
    

    
  findOne(id: string) {
    return this.userModel.findById(id);
  }

  remove(id: string) {
    return `This action removes a #${id} user`;
  }
}
