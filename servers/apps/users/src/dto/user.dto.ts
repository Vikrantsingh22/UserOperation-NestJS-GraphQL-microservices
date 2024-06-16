import { InputType, Field } from '@nestjs/graphql';
import {
  IsEmail,
  IsNotEmpty,
  IsPhoneNumber,
  IsString,
  MinLength,
  isNotEmpty,
  isString,
} from 'class-validator';

@InputType()
// here we are using the input type beacsue we are not using the
// controller
export class RegisterDto {
  @Field()
  @IsNotEmpty({ message: 'Name is required: ' })
  @IsString({ message: 'Name must need to be one string' })
  name: string;

  @Field()
  @IsNotEmpty({ message: 'Email is required ' })
  @IsEmail({}, { message: 'Email is required' })
  email: string;
  @Field()
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be atleast 8 characters' })
  password: string;

  @Field()
  @IsNotEmpty({ message: 'Phone number is required' })
  phone_number: number;
}

@InputType()
export class LoginDto {
  @Field()
  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Email must be valid' })
  email: string;
  @Field()
  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}

@InputType()
export class ActivationDto {
  @Field()
  @IsNotEmpty({
    message: 'Activation Token is required',
  })
  activationToken: string;
  @Field()
  @IsNotEmpty({
    message: 'Activation code is required',
  })
  activationCode: string;
}

@InputType()
export class ForgotPasswordDto {
  @Field()
  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Email must be valid' })
  email: string;
}

@InputType()
export class ResetPasswordDto {
  @Field()
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password is small' })
  password: string;
  @Field()
  @IsNotEmpty({ message: 'Activation Token is required' })
  activationToken: string;
}
