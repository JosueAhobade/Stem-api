import { Controller , Post , Body , Patch , Param , Delete , UseGuards , Get , Req  } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { AuthGuard } from '../auth/auth.guard';

@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) {}

    @Post()
    create(@Body() createUserDto: CreateUserDto) {
      return this.usersService.create(createUserDto);
    }

    @UseGuards(AuthGuard)
  @Get('myInfos')
  myInfos(@Req() req){
      return this.usersService.findOne(req.user.id)
  }

    @Patch(':id')
    update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
      console.log("updateUserDto",updateUserDto)
      return this.usersService.update(id, updateUserDto);
    }

    @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }
}
