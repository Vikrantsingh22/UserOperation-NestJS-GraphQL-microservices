import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, JwtVerifyOptions } from '@nestjs/jwt';
import {
  ActivationDto,
  ForgotPasswordDto,
  LoginDto,
  RegisterDto,
  ResetPasswordDto,
} from './dto/user.dto';
import { retry } from 'rxjs';
import { PrismaService } from '../../../prisma/Prisma.service';
import { Response } from 'express';
import * as bcrypt from 'bcrypt';
import { EmailService } from './email/email.service';
import { TokenSender } from './utils/sendToken';
import { error } from 'console';
import { User } from '@prisma/client';

interface UserData {
  name: string;
  email: string;
  password: string;
  phone_number: number;
}

@Injectable()
export class UsersService {
  constructor(
    private readonly jwtService: JwtService,

    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
    private readonly emailService: EmailService,
  ) {}
  async register(RegisterDto: RegisterDto, response: Response) {
    console.log('Register route');
    const { name, email, password, phone_number } = RegisterDto;
    const isEmailExist = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
    const IsPhoneNumberExist = await this.prisma.user.findUnique({
      where: {
        phone_number,
      },
    });
    if (isEmailExist) {
      throw new BadRequestException('User Already exist');
    }
    if (IsPhoneNumberExist) {
      throw new BadRequestException(
        'User with same phoen number already exist',
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    // const user = await this.prisma.user.create({
    //   data: { email, name, password: hashedPassword, phone_number },
    // });
    const user = { email, name, password: hashedPassword, phone_number };
    const activationToken = await this.createActivationToken(user);
    const activationCode = activationToken.activationCode;
    console.log(activationCode);
    const activation_token = activationToken.token;
    await this.emailService.sendMail({
      email,
      subject: 'Activate your account!',
      template: './activation-mail',
      name,
      activationCode,
    });
    return { activation_token, response };
  }

  async createActivationToken(user: UserData) {
    const activationCode = Math.floor(1000 + Math.random() * 9000).toString();
    const token = this.jwtService.sign(
      {
        user,
        activationCode,
      },
      {
        secret: this.configService.get<string>('ACTIVATION_CODE'),
        expiresIn: '5m',
      },
    );
    return { token, activationCode };
  }

  async activateUSer(activationDto: ActivationDto, response: Response) {
    const { activationToken, activationCode } = activationDto;
    const newUser: {
      user: UserData;
      activationCode: string;
    } = this.jwtService.verify(activationToken, {
      secret: this.configService.get<string>('ACTIVATION_CODE'),
    } as JwtVerifyOptions) as { user: UserData; activationCode: string };
    if (newUser.activationCode !== activationCode) {
      throw new BadRequestException('Invalid activation code');
    }
    const { name, email, password, phone_number } = newUser.user;
    const existUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (existUser) {
      throw new BadRequestException('User already exist with this email!');
    }
    const user = await this.prisma.user.create({
      data: {
        name,
        email,
        password,
        phone_number,
      },
    });
    return { user };
  }
  // login service
  async Login(loginDto: LoginDto) {
    console.log('Route hit');
    const { email, password } = loginDto;
    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (user && (await this.comparePassword(password, user.password))) {
      const tokenSender = new TokenSender(this.configService, this.jwtService);
      return tokenSender.sendToken(user);
    } else {
      // throw new BadRequestException('Invalid credentials');
      return {
        user: null,
        accessToken: null,
        refreshToken: null,
        error: {
          message: 'Invalid email or password',
        },
      };
    }
  }
  async comparePassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword);
  }
  // get logged in user
  async getLoggedInUser(req: any) {
    const user = req.user;
    const refreshToken = req.refreshToken;
    const accessToken = req.accessToken;
    return { user, refreshToken, accessToken };
  }

  async Logout(req: any) {
    req.user = null;
    req.refreshToken = null;
    req.accessToken = null;
    console.log(req.refreshToken);
    return { message: 'User logged out successfully' };
  }
  // forgot password link
  async generateForgotPassword(user: User) {
    const forgotPasswordToken = this.jwtService.sign(
      {
        user,
      },
      {
        secret: this.configService.get<string>('FORGOT_PASSWORD_SECRET'),
        expiresIn: '5m',
      },
    );
    return forgotPasswordToken;
  }
  // forgot Password

  async ForgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;
    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (!user) {
      throw new BadRequestException('User not found with this email !');
    }
    const forgotPasswordToken = await this.generateForgotPassword(user);
    console.log(forgotPasswordToken);
    const resetPasswordUrl =
      this.configService.get<string>('CLIENT_SIDE_URI') +
      `/resetpassword?verify=${forgotPasswordToken}`;
    await this.emailService.sendMail({
      email,
      subject: 'Resest Your Password!',
      template: './forgotpassword',
      name: user.name,
      activationCode: resetPasswordUrl,
    });
    return { message: 'The request is served successfully' };
  }

  // reset Password
  async resetPassword(resestPasswordDto: ResetPasswordDto) {
    const { password, activationToken } = resestPasswordDto;
    const decoded = await this.jwtService.decode(activationToken);
    if (!decoded) {
      throw new BadRequestException('Invalid token');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await this.prisma.user.update({
      where: {
        id: decoded.user.id,
      },
      data: {
        password: hashedPassword,
      },
    });
    return { user };
  }
  // get all user
  async getUser() {
    // const users = [
    //   {
    //     id: '1234',
    //     name: 'test',
    //     email: 'abc@gmail.com',
    //     password: '12456',
    //   },
    // ];
    return this.prisma.user.findMany({});
  }
}
