import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';

import { AuthService } from './auth.service';

import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto } from './dto/index';
import { AuthGuard } from './guards/auth.guard';
import { LoginResponse } from './interfaces/login-response';
import { User } from './entities/user.entity';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('/register')
  register(@Body() registerDto: RegisterUserDto ) {
    return this.authService.register( registerDto );
  }

  @Post('/login')
  login(@Body() loginDto: LoginDto ): Promise<LoginResponse> {
    return this.authService.login( loginDto );
  }

  @UseGuards( AuthGuard )
  @Get('/check-token')
  checkToken( @Request() request: Request ): LoginResponse {
    const user = request['user'] as User;
    return {
      user,
      token: this.authService.getJwtToken( { id: user._id } )
    };
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll( @Request() request: Request ) {
    return this.authService.findAll();
  }

  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.authService.findOne(+id);
  // }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
  //   return this.authService.update(+id, updateAuthDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.authService.remove(+id);
  // }
}
